/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>

#include "m_mem.h"
#include "m_list.h"
#include "m_stm.h"
#include "m_debug.h"
#include "m_rc4.h"

#include "mnet_core.h"
#include "plat_time.h"
#include "plat_thread.h"

#include "utils_str.h"
#include "utils_conf.h"
#include "utils_misc.h"

#include "tunnel_cmd.h"
#include "tunnel_dns.h"
#include "tunnel_conf.h"

#include <assert.h>

#define _err(...) _mlog("remote", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog("remote", D_INFO, __VA_ARGS__)
#define _verbose(...) _mlog("remote", D_VERBOSE, __VA_ARGS__)

#ifdef TEST_TUNNEL_REMOTE

#define TUNNEL_REMOTE_MAX_CLIENT (16)

typedef enum {
   REMOTE_CLIENT_STATE_NONE = 0,
   REMOTE_CLIENT_STATE_ACCEPT,  /* AUTH successful */
} remote_client_state_t;

/* chann state to front */
typedef enum {
   REMOTE_CHANN_STATE_CLOSED = 0,
   REMOTE_CHANN_STATE_DISCONNECT, /* chann tcpout disconnect */
   REMOTE_CHANN_STATE_CONNECTING, /* chann tcpout connecting */
   REMOTE_CHANN_STATE_CONNECTED,  /* chann tcpout connected */
} remote_chann_state_t;

typedef struct {
   char addr[TUNNEL_DNS_ADDR_LEN];
   int port;
   u16 chann_id;
   u16 magic;
   void *opaque;
} dns_query_t;

typedef struct {
   remote_chann_state_t state;
   u16 chann_id;                /* chann id in slots */
   u16  magic;                  /* from local chann magic */
   chann_t *tcpout;
   buf_t *bufout;
   lst_node_t *node;            /* node in active_lst */
   void *client;                /* client pointer */
} tun_remote_chann_t;

typedef struct {
   remote_client_state_t state;
   chann_t *tcpin;
   buf_t *bufin;
   lst_t *active_lst;
   lst_t *free_lst;
   lst_t *want_lst;             /* chann_id/magic wanted */
   lst_node_t *node;            /* node in clients_lst */
   tun_remote_chann_t *channs[TUNNEL_CHANN_MAX_COUNT];
} tun_remote_client_t;

typedef struct {
   int running;
   time_t ti;
   time_t last_ti;
   uint64_t key;
   tunnel_config_t conf;
   chann_t *tcpin;
   buf_t *buftmp;               /* buf for crypto */
   lst_t *clients_lst;          /* acitve cilent */
   lst_t *leave_lst;            /* client to leave */
   stm_t *ip_stm;
} tun_remote_t;

static tun_remote_t _g_remote;

static void _remote_tcpout_cb(chann_msg_t *e);
static void _remote_tcpin_cb(chann_msg_t *e);
static void _remote_chann_close(tun_remote_chann_t*, int line);

static inline tun_remote_t* _tun_remote(void) {
   return &_g_remote;
}

static dns_query_t*
_dns_query_create(int port, u16 chann_id, u16 magic, void *opaque) {
   dns_query_t *q = (dns_query_t*)mm_malloc(sizeof(*q));
   q->port = port;
   q->chann_id = chann_id;
   q->magic = magic;
   q->opaque = opaque;
   return q;
}

static void
_dns_query_destroy(dns_query_t *query) {
   mm_free(query);
}

static tun_remote_client_t*
_remote_client_create(chann_t *n) {
   tun_remote_t *tun = _tun_remote();
   tun_remote_client_t *c = (tun_remote_client_t*)mm_malloc(sizeof(*c));
   c->tcpin = n;
   c->bufin = buf_create(TUNNEL_CHANN_BUF_SIZE);
   assert(c->bufin);
   c->active_lst = lst_create();
   c->free_lst = lst_create();
   c->want_lst = lst_create();
   c->node = lst_pushl(tun->clients_lst, c);
   mnet_chann_set_bufsize(n, 262144);
   mnet_chann_set_cb(n, _remote_tcpin_cb, c);
   return c;
}

static void
_remote_client_destroy(tun_remote_client_t *c) {
   tun_remote_t *tun = _tun_remote();
   if (c->node) {
      mnet_chann_set_cb(c->tcpin, NULL, NULL);
      if (mnet_chann_state(c->tcpin) >= CHANN_STATE_CONNECTING) {
         mnet_chann_close(c->tcpin);
      }

      buf_destroy(c->bufin);
      c->bufin = NULL;

      while (lst_count(c->active_lst) > 0) {
         tun_remote_chann_t *rc = lst_first(c->active_lst);
         _remote_chann_close(rc, __LINE__);
      }
      lst_destroy(c->active_lst);

      while (lst_count(c->free_lst) > 0) {
         tun_remote_chann_t *rc = lst_popf(c->free_lst);
         buf_destroy(rc->bufout);
         mm_free(rc);
      }
      lst_destroy(c->free_lst);

      while (lst_count(c->want_lst) > 0) {
         mm_free(lst_popf(c->want_lst));
      }
      lst_destroy(c->want_lst);

      lst_remove(tun->clients_lst, c->node);
      c->node = NULL;
      mm_free(c);
      _verbose("client destroy %p\n", c);
   }
}

static tun_remote_chann_t*
_remote_chann_open(tun_remote_client_t *c, tunnel_cmd_t *tcmd, char *addr, int port) {
   tun_remote_chann_t *rc = c->channs[tcmd->chann_id];
   if (rc && rc->chann_id==tcmd->chann_id && rc->magic==tcmd->magic) {
      return rc;
   }

   if (lst_count(c->free_lst) > 0) {
      rc = lst_popf(c->free_lst);
   } else {
      rc = (tun_remote_chann_t*)mm_malloc(sizeof(*rc));
   }
   rc->bufout = buf_create(TUNNEL_CHANN_BUF_SIZE);
   assert(rc->bufout);

   rc->chann_id = tcmd->chann_id;
   rc->magic = tcmd->magic;
   rc->client = (void*)c;
   rc->node = lst_pushl(c->active_lst, rc);
   rc->tcpout = mnet_chann_open(CHANN_TYPE_STREAM);

   c->channs[tcmd->chann_id] = rc;
   mnet_chann_set_cb(rc->tcpout, _remote_tcpout_cb, rc);

   buf_reset(rc->bufout);

   if (mnet_chann_connect(rc->tcpout, addr, port) > 0) {
      if (mnet_chann_state(rc->tcpout) == CHANN_STATE_CONNECTED) {
         rc->state = REMOTE_CHANN_STATE_CONNECTED;
      } else {
         rc->state = REMOTE_CHANN_STATE_CONNECTING;
      }
      return rc;
   }
   _err("chann fail to open %u, %p\n", tcmd->chann_id, c);
   return NULL;
}

void
_remote_chann_close(tun_remote_chann_t *rc, int from_line) {
   tun_remote_client_t *c = (tun_remote_client_t*)rc->client;
   if (rc->node) {
      _verbose("(%d), chann %p %u:%u close state:%d (a:%d,f:%d)\n", from_line,
               rc->tcpout, rc->chann_id, rc->magic, mnet_chann_state(rc->tcpout),
               lst_count(c->active_lst), lst_count(c->free_lst));

      buf_destroy(rc->bufout);

      rc->bufout = NULL;
      c->channs[rc->chann_id] = NULL;
      rc->chann_id = 0;

      lst_remove(c->active_lst, rc->node);
      lst_pushl(c->free_lst, rc);

      rc->node = NULL;
      rc->state = REMOTE_CHANN_STATE_CLOSED;

      mnet_chann_disconnect(rc->tcpout);
      mnet_chann_close(rc->tcpout);
   }
}

static tun_remote_chann_t*
_remote_chann_of_id_magic(tun_remote_client_t *c, u16 chann_id, u16 magic) {
   if (c) {
      if (chann_id>=0 && chann_id<TUNNEL_CHANN_MAX_COUNT) {
         tun_remote_chann_t *rc = c->channs[chann_id];
         if (rc && (rc->chann_id==chann_id && rc->magic==magic)) {
            return rc;
         }
      }
   }
   return NULL;
}

static void
_remote_aux_dns_cb(char *addr, int addr_len, void *opaque) {
   tun_remote_t *tun = _tun_remote();
   dns_query_t *q = (dns_query_t*)opaque;

   if (addr) {
      strncpy(q->addr, addr, addr_len);
   }
   else {
      q->port = 0;
   }

   stm_pushl(tun->ip_stm, q);
}

static int
_remote_send_front_data(tun_remote_client_t *c, unsigned char *buf, u16 buf_len) {
   tun_remote_t *tun = _tun_remote();

   if (tun->conf.crypto_rc4) {

      char *tbuf = (char*)buf_addr(tun->buftmp,0);
      int base = TUNNEL_CMD_CONST_DATA_LEN_OFFSET;

      u16 data_len = rc4_encrypt((char*)&buf[base], buf_len - base,
                                 &tbuf[base], buf_len(tun->buftmp)-base,
                                 tun->key, tun->ti);
      if (data_len > 0) {
         tunnel_cmd_data_len((void*)tbuf, 1, data_len + base);
         return mnet_chann_send(c->tcpin, tbuf, data_len + base);
      }
   }
   else {
      return mnet_chann_send(c->tcpin, buf, buf_len);      
   }
   return 0;
}

static int
_remote_recv_front_data(tun_remote_client_t *c, buf_t *b) {
   tun_remote_t *tun = _tun_remote();

   if (tun->conf.crypto_rc4) {
      char *buf = (char*)buf_addr(b,0);
      int buf_len = buf_buffered(b);

      char *tbuf = (char*)buf_addr(tun->buftmp,0);
      int base = TUNNEL_CMD_CONST_DATA_LEN_OFFSET;      

      u16 data_len = rc4_decrypt(&buf[base], buf_len-base,
                                 tbuf, buf_len(tun->buftmp),
                                 tun->key, tun->ti);
      if (data_len <= 0) {
         _err("invalid data_len !\n");
         return 0;
      }

      memcpy(&buf[base], tbuf, data_len);
      tunnel_cmd_data_len((void*)buf, 1, data_len + base);

      buf_reset(b);
      buf_forward_ptw(b, data_len + base);
   }
   return 1;
}

static void
_remote_send_connect_result(tun_remote_client_t *c, u16 chann_id, u16 magic, int result) {
   unsigned char data[32] = {0};

   u16 hlen = TUNNEL_CMD_CONST_HEADER_LEN;
   u16 data_len = hlen + 7;

   tunnel_cmd_data_len(data, 1, data_len);
   tunnel_cmd_chann_id(data, 1, chann_id);
   tunnel_cmd_chann_magic(data, 1, magic);
   tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_CONNECT);
   
   data[hlen] = result;

   if (result > 0) {
      tun_remote_chann_t *rc = _remote_chann_of_id_magic(c, chann_id, magic);

      if (rc) {
         chann_addr_t addr;
         mnet_chann_addr(rc->tcpout, &addr);

         data[hlen + 1] = (addr.port >> 8) & 0xff;
         data[hlen + 2] = addr.port & 0xff;

         misc_hex_addr(addr.ip, strlen(addr.ip), &data[hlen+3], 4);

      } else {
         _err("fail to get connect result %u:%u\n", chann_id, magic);
         data[hlen] = 0;
      }
   }

   int ret = _remote_send_front_data(c, data, data_len);
   if (ret < data_len) {
      _err("fail to send connect result %d, %u!\n", ret, data_len);
   }
}

static inline time_t
_remote_update_ti() {
   time_t ti = time(NULL);
   _tun_remote()->ti = ti;
   return ti;
}

static void
_remote_send_echo(tun_remote_client_t *c) {
   unsigned char data[32] = {0};
   u16 data_len = TUNNEL_CMD_CONST_HEADER_LEN + 1;
   memset(data, 0, sizeof(data));

   tunnel_cmd_data_len(data, 1, data_len);
   tunnel_cmd_chann_id(data, 1, 0);
   tunnel_cmd_chann_magic(data, 1, 0);
   tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_ECHO);
   data[data_len - 1] = 1;

   _remote_send_front_data(c, data, data_len);
   _remote_update_ti();

   _verbose("response echo to %p\n", c);
}

static void
_remote_send_close(tun_remote_client_t *c, tun_remote_chann_t *rc, int result) {
   unsigned char data[16] = {0};

   u16 data_len = TUNNEL_CMD_CONST_HEADER_LEN + 1;

   tunnel_cmd_data_len(data, 1, data_len);
   tunnel_cmd_chann_id(data, 1, rc->chann_id);
   tunnel_cmd_chann_magic(data, 1, rc->magic);
   tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_CLOSE);

   data[data_len - 1] = result; /* omit */

   _remote_send_front_data(c, data, data_len);
}

int
_remote_chann_in_want_lst(tun_remote_client_t *c, tunnel_cmd_t *tcmd) {
   int is_want = 0;
   lst_foreach(it, c->want_lst) {
      tunnel_cmd_t *ptcmd = lst_iter_data(it);
      if (ptcmd->chann_id==tcmd->chann_id && ptcmd->magic==tcmd->magic) {
         mm_free(ptcmd);
         lst_iter_remove(it);
         is_want = 1;
      }
   }
   return is_want;
}

void
_remote_tcpin_cb(chann_msg_t *e) {
   tun_remote_client_t *c = (tun_remote_client_t*)e->opaque;
   if (c->bufin == NULL) {
      return;
   }

   if (e->event == CHANN_EVENT_RECV) {
      tunnel_cmd_t tcmd = {0, 0, 0, 0, NULL};

      for (;;) {
         int ret = 0;
         buf_t *ib = c->bufin;

         if (buf_buffered(ib) < TUNNEL_CMD_CONST_HEADER_LEN) {
            ret = mnet_chann_recv(e->n, buf_addr(ib,buf_ptw(ib)), TUNNEL_CMD_CONST_HEADER_LEN - buf_buffered(ib));
         } else {
            tunnel_cmd_check(ib, &tcmd);
            ret = mnet_chann_recv(e->n, buf_addr(ib,buf_ptw(ib)), tcmd.data_len - buf_buffered(ib));
         }

         if (ret <= 0) {
            return;
         }
         buf_forward_ptw(ib, ret);

         if (buf_buffered(ib) <= TUNNEL_CMD_CONST_HEADER_LEN) {
            return;
         }
         if (tcmd.data_len != buf_buffered(ib)) {
            return;
         }

         /* decode data */
         if (_remote_recv_front_data(c, ib) <= 0) {
            goto reset_buffer;
         }

         /* _verbose("%d, %d\n", tcmd.data_len, buf_buffered(ib)); */
         tunnel_cmd_check(ib, &tcmd);
         if (tcmd.cmd<=TUNNEL_CMD_NONE || tcmd.cmd>TUNNEL_CMD_DATA) {
            goto reset_buffer;
         }


         if (tcmd.cmd == TUNNEL_CMD_ECHO) {
            _remote_send_echo(c);
            goto reset_buffer;
         }

         /* _info("get cmd %d\n", tcmd.cmd); */
         if (c->state == REMOTE_CLIENT_STATE_ACCEPT) {

            if (tcmd.cmd == TUNNEL_CMD_DATA) {
               tun_remote_chann_t *rc = _remote_chann_of_id_magic(c, tcmd.chann_id, tcmd.magic);

               if (rc && rc->state==REMOTE_CHANN_STATE_CONNECTED) {
                  int hlen = TUNNEL_CMD_CONST_HEADER_LEN;
                  mnet_chann_send(rc->tcpout, tcmd.payload, tcmd.data_len - hlen);
               }
            }
            else if (tcmd.cmd == TUNNEL_CMD_CONNECT) {
               unsigned char *payload = tcmd.payload;
               unsigned char addr_type = payload[0];

               int port = ((payload[1] & 0xff) << 8) | (payload[2] & 0xff);
               /* _verbose("chann %d addr_type %d\n", tcmd.chann_id, addr_type); */

               if (addr_type == TUNNEL_ADDR_TYPE_IP) {
                  char addr[TUNNEL_DNS_ADDR_LEN] = {0};

                  strcpy(addr, (const char*)&payload[3]);
                  _verbose("chann %u:%u try connect ip [%s:%d], %d\n", tcmd.chann_id,
                           tcmd.magic, addr, port, strlen(addr));

                  tun_remote_chann_t *rc = _remote_chann_open(c, &tcmd, addr, port);
                  if (rc == NULL) {
                     _remote_send_connect_result(c, tcmd.chann_id, tcmd.magic, 0);
                  }
               }
               else {
                  char addr[TUNNEL_DNS_DOMAIN_LEN] = {0};
                  char domain[TUNNEL_DNS_DOMAIN_LEN] = {0};

                  strcpy(domain, (const char*)&payload[3]);
                  _verbose("chann %u:%u query domain [%s:%d], %d\n",
                           tcmd.chann_id, tcmd.magic, domain, port, strlen(addr));

                  tunnel_cmd_t *ptcmd = (tunnel_cmd_t*)mm_malloc(sizeof(tunnel_cmd_t));
                  *ptcmd = tcmd;
                  lst_pushf(c->want_lst, ptcmd);
                  
                  dns_query_t *query_entry = _dns_query_create(port, tcmd.chann_id, tcmd.magic, c);
                  dns_query_domain(domain, strlen(domain), _remote_aux_dns_cb, query_entry);
               }
            }
            else if (tcmd.cmd == TUNNEL_CMD_CLOSE) {
               tun_remote_chann_t *rc = _remote_chann_of_id_magic(c, tcmd.chann_id, tcmd.magic);
               if (rc) {
                  _remote_chann_close(rc, __LINE__);
               } else {
                  _remote_chann_in_want_lst(c, &tcmd);
               }
            }
         }
         else {
            if (tcmd.cmd == TUNNEL_CMD_AUTH) {
               unsigned char data[64] = {0};
               u16 data_len = TUNNEL_CMD_CONST_HEADER_LEN + 1;

               int auth_type = tcmd.payload[0];
            
               if (auth_type == 1) {
                  char *username = (char*)&tcmd.payload[1];
                  char *passwd = (char*)&tcmd.payload[17];

                  tunnel_cmd_data_len(data, 1, data_len);
                  tunnel_cmd_chann_id(data, 1, 0);
                  tunnel_cmd_chann_magic(data, 1, 0);
                  tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_AUTH);

                  tun_remote_t *tun = _tun_remote();
                  if (strncmp(tun->conf.username, username, 16)==0 &&
                      strncmp(tun->conf.password, passwd, 16)==0)
                  {
                     c->state = REMOTE_CLIENT_STATE_ACCEPT;
                     data[data_len - 1] = 1;
                     _remote_send_front_data(c, data, data_len);
                  }
                  else {
                     data[data_len - 1] = 0;
                     _err("fail to auth <%s>, <%s>\n", username, passwd);
                     _remote_client_destroy(c);
                  }
               }
               _verbose("(in) accept client %p, %d\n", c, auth_type);
            }
            else {
               _err("invalid command !\n");
            }
         }
        reset_buffer:
         buf_reset(ib);
      }
   }
   else if (e->event == CHANN_EVENT_DISCONNECT)
   {
      _verbose("client %p close event !\n", c);
      lst_pushl(_tun_remote()->leave_lst, c);
   }
}

static inline int
_remote_buf_available(buf_t *b) {
   return (buf_available(b) - RC4_CRYPTO_OCCUPY); /* keep space for RC4 crypto */
}

void
_remote_tcpout_cb(chann_msg_t *e) {
   tun_remote_chann_t *rc = (tun_remote_chann_t*)e->opaque;
   tun_remote_client_t *c = (tun_remote_client_t*)rc->client;
   
   if (e->event == CHANN_EVENT_RECV) {
      if (c->state == REMOTE_CLIENT_STATE_ACCEPT) {
         buf_t *ob = rc->bufout;
         int hlen = TUNNEL_CMD_CONST_HEADER_LEN;
         int ret = mnet_chann_recv(e->n, buf_addr(ob,hlen), _remote_buf_available(ob) - hlen);
         if (ret <= 0) {
            return;
         }

         u16 data_len = ret + hlen;
         buf_forward_ptw(ob, data_len);

         unsigned char *data = buf_addr(ob,0);

         tunnel_cmd_data_len(data, 1, data_len);
         tunnel_cmd_chann_id(data, 1, rc->chann_id);
         tunnel_cmd_chann_magic(data, 1, rc->magic);
         tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_DATA);

         _remote_send_front_data(c, data, data_len);

         buf_reset(ob);
      }
   }
   else if (e->event == CHANN_EVENT_CONNECTED) {
      if (rc->state < REMOTE_CHANN_STATE_CONNECTED) {
         _verbose("(out) chann %p %u:%u connected\n", rc->tcpout, rc->chann_id, rc->magic);
         rc->state = REMOTE_CHANN_STATE_CONNECTED;
         _remote_send_connect_result(c, rc->chann_id, rc->magic, 1);
      }
   }
   else if (e->event == CHANN_EVENT_DISCONNECT)
   {
      _verbose("(out) chann %u:%u close, mnet\n", rc->chann_id, rc->magic);
      _remote_send_close(c, rc, 1);
      _remote_chann_close(rc, __LINE__);
   }
}

static void
_remote_listen_cb(chann_msg_t *e) {
   if (e->event == CHANN_EVENT_ACCEPT) {
      tun_remote_t *tun = _tun_remote();
      if (lst_count(tun->clients_lst) < TUNNEL_REMOTE_MAX_CLIENT) {
         _remote_client_create(e->r);
      }
   }
}

static void
_remote_stm_finalizer(void *ptr, void *ud) {
   mm_free(ptr);
}

int
tunnel_remote_open(tunnel_config_t *conf) {
   tun_remote_t *tun = _tun_remote();
   if (conf && !tun->running) {
      memset(tun, 0, sizeof(*tun));

      tun->conf = *conf;
      tun->clients_lst = lst_create();
      tun->leave_lst = lst_create();
      tun->ip_stm = stm_create("remote_dns_cache", _remote_stm_finalizer, tun);

      tun->tcpin = mnet_chann_open(CHANN_TYPE_STREAM);
      mnet_chann_set_cb(tun->tcpin, _remote_listen_cb, tun);
      if (mnet_chann_listen_ex(tun->tcpin, conf->remote_ipaddr, conf->remote_port, 2) <= 0) {
         exit(1);
      }

      tun->buftmp = buf_create(TUNNEL_CHANN_BUF_SIZE + 32);
      assert(tun->buftmp);

      tun->running = 1;

      _info("remote listen on %s:%d\n", conf->local_ipaddr, conf->local_port);
      _info("\n");

      return 1;
   }
   return 0;
}

static tun_remote_client_t*
_remote_active_client(tun_remote_client_t *c) {
   tun_remote_t *tun = _tun_remote();
   lst_foreach(it, tun->clients_lst) {
      tun_remote_client_t *lc = lst_iter_data(it);
      if (lc == c) {
         return c;
      }
   }
   return NULL;
}

int
main(int argc, char *argv[]) {
   if (argc != 2) {
      printf("[remote] %s REMOTE_CONFIG_FILE\n", argv[0]);
      return 0;
   }

   signal(SIGPIPE, SIG_IGN);

   tunnel_config_t conf;

   if ( !tunnel_conf_get_values(&conf, argv) ) {
      return 0;
   }

   debug_open(conf.dbg_fname);
   debug_set_option(D_OPT_FILE);
   debug_set_level(D_VERBOSE);

   stm_init();
   mnet_init();
   dns_init();

   if (tunnel_remote_open(&conf) > 0) {
      tun_remote_t *tun = _tun_remote();

      tun->last_ti = _remote_update_ti();
      tun->key = rc4_hash_key(conf.password, strlen(conf.password));

      for (int i=0;;i++) {

         _remote_update_ti();
         mnet_poll( 1 << (MNET_ONE_SECOND_BIT + 1) );

         /* close inactive client */
         while (lst_count(tun->leave_lst) > 0) {
            _remote_client_destroy(lst_popf(tun->leave_lst));
         }

         /* check dns ip_stm, and create chann_id/magic paired socket */
         while (stm_count(tun->ip_stm) > 0) {
            dns_query_t *q = stm_popf(tun->ip_stm);
            tun_remote_client_t *c = q->opaque;

            if ( _remote_active_client(c) ) {
               tunnel_cmd_t tcmd;
               int is_connect = 1;

               tcmd.chann_id = q->chann_id;
               tcmd.magic = q->magic;

               /* check dns query chann_id/magic not in close_lst */
               if ( _remote_chann_in_want_lst(c, &tcmd) ) {
                  if (q->port <= 0) {
                     is_connect = 0;
                  } else {
                     tun_remote_chann_t *rc = _remote_chann_open(c, &tcmd, q->addr, q->port);
                     if (rc == NULL) {
                        is_connect = 0;
                     }
                  }
               }

               if ( !is_connect ) {
                  _remote_send_connect_result(c, tcmd.chann_id, tcmd.magic, 0);
               }
            }
               
            _dns_query_destroy(q);
         }

         /* mem report */
         if (tun->ti - tun->last_ti > 60) {
            tun->last_ti = tun->ti;
            mm_report(1);
            _verbose("channs count:%d\n", mnet_report(0));
         }
      }
   }

   dns_fini();
   stm_fini();
   mnet_fini();
   debug_close();
   return 0;
}

#endif  /* TEST_TUNNEL_REMOTE */
