/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <io.h>
#include <process.h>
#include <time.h>
#else
#include <unistd.h>
#include <sys/time.h>
#endif
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

#include "m_mem.h"
#include "m_buf.h"
#include "m_list.h"
#include "m_debug.h"
#include "m_rc4.h"

#include "plat_type.h"
#include "plat_net.h"
#include "plat_time.h"

#include "utils_str.h"
#include "utils_conf.h"
#include "utils_misc.h"

#include "tunnel_cmd.h"
#include "tunnel_dns.h"
#include "tunnel_local.h"

#include <assert.h>

#define _err(...) _mlog("local", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog("local", D_INFO, __VA_ARGS__)
#define _verbose(...) _mlog("local", D_VERBOSE, __VA_ARGS__)

#define LOCAL_TIMEOUT_SECOND 16

#ifdef TEST_TUNNEL_LOCAL

/* state to remote */
typedef enum {
   LOCAL_CHANN_STATE_NONE = 0,       /* init state */
   LOCAL_CHANN_STATE_WAIT_LOCAL,     /* opened, need to recieve '05 01 00' */
   LOCAL_CHANN_STATE_ACCEPT,         /* connected local, send '05 00' */
   LOCAL_CHANN_STATE_DISCONNECT,     /* disconnect from remote, no need to send close */
   LOCAL_CHANN_STATE_WAIT_REMOTE,    /* wait remote connected */
   LOCAL_CHANN_STATE_CONNECTED,      /* remote connected */
} local_chann_state_t;

/* for mode front */
typedef enum {
   LOCAL_FRONT_STATE_NONE = 0,        /* have not connect serv */
   LOCAL_FRONT_STATE_CONNECTED,
   LOCAL_FRONT_STATE_AUTHORIZED,
} local_front_state_t;

typedef struct {
   local_chann_state_t state;
   u16 chann_id;                /* chann id in slots  */
   u16 magic;                    /* unique chann magic in chann slots */
   chann_t *tcpin;              /* for input */
   buf_t *bufin;                /* buf for input */
   lst_node_t *node;            /* node in active_list */
} tun_local_chann_t;

typedef struct {
   int running;                 /* running status */
   time_t ti;
   time_t last_ti;
   uint64_t key;
   int data_mark;
   u16 chann_idx;
   u16 magic_code;
   tunnel_local_mode_t mode;
   local_front_state_t state;
   tunnel_local_config_t conf;
   chann_t *tcpin;              /* tcp for listen */
   chann_t *tcpout;             /* tcp for forward */
   buf_t *bufout;               /* buf for forward */
   buf_t *buftmp;               /* buf for crypto */
   lst_t *active_lst;           /* active chann list */
   lst_t *free_lst;             /* free chann list */
   int reset_connection;
   tun_local_chann_t *channs[TUNNEL_CHANN_MAX_COUNT];
} tun_local_t;

static tun_local_t _g_local;

static void _local_chann_tcpin_cb_front(chann_event_t *e);
static void _local_tcpout_cb_front(chann_event_t *e);
void tunnel_local_close(void);

static inline tun_local_t* _tun_local(void) {
   return &_g_local;
}

/* description: chann r from local listen
 */
static void
_local_chann_open(chann_t *r) {
   tun_local_t *tun = _tun_local();
   tun_local_chann_t *c = NULL;
   if (lst_count(tun->free_lst) > 0) {
      c = (tun_local_chann_t*)lst_popf(tun->free_lst);
   }
   else {
      c = (tun_local_chann_t*)mm_malloc(sizeof(*c));
      c->bufin = buf_create(TUNNEL_CHANN_BUF_SIZE);
      assert(c->bufin);
      c->chann_id = tun->chann_idx;
      tun->chann_idx += 1;
   }
   tun->channs[c->chann_id] = c;
   c->magic = (++tun->magic_code);
   c->tcpin = r;
   c->node = lst_pushl(tun->active_lst ,c);
   buf_reset(c->bufin);

   if (tun->mode == TUNNEL_LOCAL_MODE_FRONT) {
      c->state = LOCAL_CHANN_STATE_WAIT_LOCAL; /* wait local connect cmd */
      mnet_chann_set_cb(c->tcpin, _local_chann_tcpin_cb_front, c);
   }
}

/* description: free local resources
 */
static void
_local_chann_close(tun_local_chann_t *c) {
   tun_local_t *tun = _tun_local();
   if (c->node) {
      _verbose("chann %p %u:%u close, state:%d (a:%d,f:%d)\n", c->tcpin, c->chann_id, c->magic,
               mnet_chann_state(c->tcpin), lst_count(tun->active_lst), lst_count(tun->free_lst));

      mnet_chann_set_cb(c->tcpin, NULL, NULL);
      mnet_chann_close(c->tcpin);

      tun->channs[c->chann_id] = NULL;
      lst_remove(tun->active_lst, c->node);
      lst_pushl(tun->free_lst, c);

      c->node = NULL;
      c->state = LOCAL_CHANN_STATE_NONE;
   }
}

static int
_hex_equal(uint8_t *s, int slen, uint8_t *e, int elen) {
   int mlen = _MIN_OF(slen, elen);

   for (int i=0; i<mlen; i++) {
      if (s[i] != e[i]) {
         return 0;
      }
   }

   return 1;
}

static void
_local_cmd_send_accept(chann_t *n, uint8_t val) {
   uint8_t ss[2] = {0x05, val};
   mnet_chann_send(n, ss, 2);
}

static void
_local_cmd_fail_to_connect(chann_t *n) {
   /* fail to connect */
   uint8_t es[10] = {0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
   mnet_chann_send(n, es, 10);
}

static void
_local_cmd_send_connected(tun_local_chann_t *c, uint8_t *addr, int port) {
   uint8_t es[10] = {
      0x05, 0x00, 0x00, 0x01,
      addr[0], addr[1], addr[2], addr[3],
      ((port & 0xff00)>>8), (port&0xff)
   };

   /* _print_hex(es, 10); */
   mnet_chann_send(c->tcpin, es, 10);
   c->state = LOCAL_CHANN_STATE_CONNECTED;
}

static int
_front_send_remote_data(unsigned char *buf, u16 buf_len) {
   tun_local_t *tun = _tun_local();

   if (tun->conf.crypto_rc4) {

      char *tbuf = (char*)buf_addr(tun->buftmp,0);
      int base = TUNNEL_CMD_CONST_DATA_LEN_OFFSET;

      u16 data_len = rc4_encrypt((char*)&buf[base], buf_len - base,
                                 &tbuf[base], buf_len(tun->buftmp)-base,
                                 tun->key, tun->ti);
      if (data_len > 0) {
         tunnel_cmd_data_len((u8*)tbuf, 1, data_len + base);
         return mnet_chann_send(tun->tcpout, tbuf, data_len + base);
      }
   }
   else {
      return mnet_chann_send(tun->tcpout, buf, buf_len);
   }
   return 0;
}

static int
_front_recv_remote_data(buf_t *b) {
   tun_local_t *tun = _tun_local();

   if (tun->conf.crypto_rc4) {
      char *buf = (char*)buf_addr(b,0);
      int buf_len = buf_buffered(b);

      char *tbuf = (char*)buf_addr(tun->buftmp,0);
      int base = TUNNEL_CMD_CONST_DATA_LEN_OFFSET;

      u16 data_len = rc4_decrypt(&buf[base], buf_len-base,
                                 tbuf, buf_len(tun->buftmp), tun->key, tun->ti);
      if (data_len <= 0) {
         _err("invalid data_len !\n");
         return 0;
      }

      memcpy(&buf[base], tbuf, data_len);
      tunnel_cmd_data_len((u8*)buf, 1, data_len + base);

      buf_reset(b);
      buf_forward_ptw(b, data_len + base);
   }
   return 1;
}

static void
_front_cmd_connect(tun_local_chann_t *fc, int addr_type, char *addr, int port) {
   uint8_t data[TUNNEL_DNS_DOMAIN_LEN + 32] = {0};
   memset(data, 0, TUNNEL_DNS_ADDR_LEN);

   int addr_offset = TUNNEL_CMD_CONST_HEADER_LEN;
   int addr_len = strlen(addr);

   u16 data_len = addr_offset + 3 + addr_len + 1;
   
   tunnel_cmd_data_len(data, 1, data_len);
   tunnel_cmd_chann_id(data, 1, fc->chann_id);
   tunnel_cmd_chann_magic(data, 1, fc->magic);
   tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_CONNECT);

   data[addr_offset + 0] = addr_type;         /* addr type numberic */
   data[addr_offset + 1] = (port>>8) & 0xff;
   data[addr_offset + 2] = port & 0xff;

   strcpy((char*)&data[addr_offset + 3], addr);

   _front_send_remote_data(data, data_len);

   fc->state = LOCAL_CHANN_STATE_WAIT_REMOTE;
}

static void
_front_cmd_close(tun_local_chann_t *c) {
   uint8_t data[32] = {0};
   u16 head_len = TUNNEL_CMD_CONST_HEADER_LEN;

   memset(data, 0, sizeof(data));

   tunnel_cmd_data_len(data, 1, head_len + 1);
   tunnel_cmd_chann_id(data, 1, c->chann_id);
   tunnel_cmd_chann_magic(data, 1, c->magic);
   tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_CLOSE);
   data[head_len] = 1;

   int ret = _front_send_remote_data(data, head_len + 1);
   _verbose("chann %u:%u send disconnect close:%d\n",
            c->chann_id, c->magic, ret);
}

static inline int
_local_buf_available(buf_t *b) {
   /* for crypto, keep least 8 bytes */
   return (buf_available(b) - TUNNEL_CMD_CONST_HEADER_LEN);
}


void
_local_chann_tcpin_cb_front(chann_event_t *e) {
   tun_local_t *tun = _tun_local();
   tun_local_chann_t *fc = (tun_local_chann_t*)e->opaque;

   if (e->event == MNET_EVENT_RECV)
   {
      int hlen = TUNNEL_CMD_CONST_HEADER_LEN;
      buf_t *ib = fc->bufin;
      int ret = mnet_chann_recv(e->n, buf_addr(ib,hlen), _local_buf_available(ib) - hlen);
      if (ret <= 0) {
         return;
      }
      buf_forward_ptw(ib, ret + hlen);

      if (fc->state == LOCAL_CHANN_STATE_CONNECTED)
      {
         uint8_t *data = buf_addr(ib,0);
         u16 data_len = buf_buffered(ib);

         tunnel_cmd_data_len(data, 1, data_len);
         tunnel_cmd_chann_id(data, 1, fc->chann_id);
         tunnel_cmd_chann_magic(data, 1, fc->magic);
         tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_DATA);

         _front_send_remote_data(data, data_len);
      }
      else if (fc->state == LOCAL_CHANN_STATE_WAIT_LOCAL) 
      {
         if (buf_buffered(ib) >= TUNNEL_CMD_CONST_HEADER_LEN) {
            uint8_t rs1[3] = {0x05, 0x01, 0x00};
            uint8_t rs2[3] = {0x05, 0x02, 0x00};
            if (_hex_equal(buf_addr(ib,hlen), buf_buffered(ib)-hlen, rs1, 3) ||
                _hex_equal(buf_addr(ib,hlen), buf_buffered(ib)-hlen, rs2, 3))
            {
               if (tun->state == LOCAL_FRONT_STATE_AUTHORIZED) {
                  _verbose("(in) accept %p, %d\n", e->n, lst_count(tun->active_lst));
                  fc->state = LOCAL_CHANN_STATE_ACCEPT;
                  _local_cmd_send_accept(e->n, 0);
               }
               else {
                  _err("(in) not authorized, not allow connection !\n");
                  _local_cmd_send_accept(e->n, 2);
               }
            }
            else {
               _err("(in) invalid socks5 cmd:%d\n", buf_buffered(ib));
            }
         }
         else {
            assert(0);
         }
      }
      else if (fc->state == LOCAL_CHANN_STATE_ACCEPT)
      {
         if (buf_buffered(ib) >= (TUNNEL_CMD_CONST_HEADER_LEN + 3)) {
            uint8_t *rd = buf_addr(ib,hlen);
            uint8_t rs[4] = {0x05, 0x01, 0x00};
            if ( _hex_equal(rd, buf_buffered(ib)-hlen, rs, 3) ) {
               if (rd[3] == 0x01) { /* IPV4 */
                  rd = &rd[4];

                  char addr[TUNNEL_DNS_ADDR_LEN] = {0};
                  snprintf(addr, TUNNEL_DNS_ADDR_LEN, "%d.%d.%d.%d", rd[0], rd[1], rd[2], rd[3]);

                  int port = (rd[4]<<8) | rd[5];

                  _front_cmd_connect(fc, TUNNEL_ADDR_TYPE_IP, addr, port);
               }
               else if (rd[3] == 0x03) { /* domain */
                  uint8_t dlen = (uint8_t)rd[4];
                  char *domain = (char*)&rd[5];
                  int port = (rd[5+dlen]<<8) | rd[6+dlen];

                  char addr[TUNNEL_DNS_DOMAIN_LEN] = {0};
                  _err("(in) chann %u:%u try connect [%s:%d]\n", fc->chann_id, fc->magic,
                       misc_fix_str_1024(domain, dlen), port);

                  strncpy(addr, domain, dlen);
                  _front_cmd_connect(fc, TUNNEL_ADDR_TYPE_DOMAIN, addr, port);
               }
               else {
                  assert(0);
               }
            }
         }
      }

      buf_reset(ib);
   }
   else if (e->event == MNET_EVENT_DISCONNECT ||
            e->event == MNET_EVENT_ERROR)
   {
      _verbose("(in) chann %u:%u close, mnet\n", fc->chann_id, fc->magic);
      _front_cmd_close(fc);
      _local_chann_close(fc);
   }
}

static tun_local_chann_t*
_local_chann_of_cmd(tun_local_t *tun, tunnel_cmd_t *tcmd) {
   if (tcmd) {
      if (tcmd->chann_id>=0 && tcmd->chann_id<TUNNEL_CHANN_MAX_COUNT) {
         tun_local_chann_t *c = tun->channs[tcmd->chann_id];
         if (c && (c->magic == tcmd->magic)) {
            return c;
         }
      }
   }
   return NULL;
}

static void
_local_tcpout_cb_front(chann_event_t *e) {
   tun_local_t *tun = _tun_local();
   
   if (e->event == MNET_EVENT_RECV) {
      tunnel_cmd_t tcmd = {0, 0, 0, 0, NULL};

      for (;;) {
         int ret = 0;
         buf_t *ob = tun->bufout;

         if (buf_buffered(ob) < TUNNEL_CMD_CONST_HEADER_LEN) {
            ret = mnet_chann_recv(e->n, buf_addr(ob,buf_ptw(ob)), TUNNEL_CMD_CONST_HEADER_LEN - buf_buffered(ob));
         } else {
            tunnel_cmd_check(ob, &tcmd);
            ret = mnet_chann_recv(e->n, buf_addr(ob,buf_ptw(ob)), tcmd.data_len - buf_buffered(ob));
         }

         if (ret <= 0) {
            return;
         }
         buf_forward_ptw(ob, ret);

         if (buf_buffered(ob) <= TUNNEL_CMD_CONST_HEADER_LEN) {
            return;
         }

         if (tcmd.data_len != buf_buffered(ob)) {
            return;
         }

         /* decode data */
         if (_front_recv_remote_data(ob) <= 0) {
            goto reset_buffer;
         }

         tunnel_cmd_check(ob, &tcmd);
         if (tcmd.cmd<=TUNNEL_CMD_NONE || tcmd.cmd>TUNNEL_CMD_DATA) {
            assert(0);
         }

         tun->data_mark++;

         if (tcmd.cmd == TUNNEL_CMD_ECHO) {
            _verbose("(out) receive echo\n");
            goto reset_buffer;
         }

         if (tun->state == LOCAL_FRONT_STATE_AUTHORIZED) {
         
            tun_local_chann_t *fc = _local_chann_of_cmd(tun, &tcmd);

            if (fc) {
               if (tcmd.cmd == TUNNEL_CMD_DATA)
               {
                  if (fc->state == LOCAL_CHANN_STATE_CONNECTED) {
                     int data_len = tcmd.data_len - TUNNEL_CMD_CONST_HEADER_LEN;
                     mnet_chann_send(fc->tcpin, tcmd.payload, data_len);
                  }
               }
               else if (tcmd.cmd == TUNNEL_CMD_CONNECT)
               {
                  if (fc->state == LOCAL_CHANN_STATE_WAIT_REMOTE) {
                     if (tcmd.payload[0] == 1) {
                        int port = (tcmd.payload[1]<<8) | tcmd.payload[2];
                        unsigned char *d = &tcmd.payload[3];

                        _local_cmd_send_connected(fc, d, port);

                        char addr[TUNNEL_DNS_ADDR_LEN] = {0};
                        sprintf(addr, "%d.%d.%d.%d", d[0], d[1], d[2], d[3]);
                        
                        _verbose("(out) chann %u:%u connected %s:%d\n",
                                 tcmd.chann_id, tcmd.magic, addr, port);
                     }
                     else {
                        _local_cmd_fail_to_connect(fc->tcpin);
                        _verbose("(out) chann %u:%u fail to connect, state:%d\n",
                                 tcmd.chann_id, tcmd.magic, fc->state);
                     }
                  }
                  else {
                     /* _err("chann %u err state %d\n", tcmd.chann_id, fc->state); */
                  }
               }
               else if (tcmd.cmd == TUNNEL_CMD_CLOSE)
               {
                  /* _verbose("chann %u close cmd %d\n", tcmd.chann_id, tcmd.payload[0]); */
                  _local_chann_close(fc);
               }
               else {
                  /* _err("chann %u err cmd %d\n", tcmd.chann_id, tcmd.cmd); */
               }
            }
         }
         else if (tun->state == LOCAL_FRONT_STATE_CONNECTED) {
            if (tcmd.cmd == TUNNEL_CMD_AUTH) {
               if (tcmd.payload[0] == 1) {
                  tun->state = LOCAL_FRONT_STATE_AUTHORIZED;
                  _verbose("(out) got authority value %d\n", tcmd.payload[0]);
               }
            }
         }
        reset_buffer:
         buf_reset(ob);
      }
   }
   else if (e->event == MNET_EVENT_CONNECTED) {
      unsigned char data[64] = {0};
      memset(data, 0, sizeof(data));

      int head_len = TUNNEL_CMD_CONST_HEADER_LEN;
      u16 data_len = head_len + 1 + 16 + 16;

      tunnel_cmd_data_len(data, 1, data_len);
      tunnel_cmd_chann_id(data, 1, 0);
      tunnel_cmd_chann_magic(data, 1, 0);
      tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_AUTH);

      /* auth type */
      data[head_len] = 1;

      /* user name */
      int uname_base = head_len + 1;
      strncpy((char*)&data[uname_base], tun->conf.username, 16);

      /* user password */
      int passw_base = uname_base + 16;
      strncpy((char*)&data[passw_base], tun->conf.password, 16);

      _front_send_remote_data(data, data_len);

      _verbose("(out) connected, send auth request\n");
      tun->state = LOCAL_FRONT_STATE_CONNECTED;
   }
   else if (e->event == MNET_EVENT_DISCONNECT) {
      _verbose("(out) chann close\n");
      tun->state = LOCAL_FRONT_STATE_NONE;
      lst_foreach(it, tun->active_lst) {
         tun_local_chann_t *c = (tun_local_chann_t*)lst_iter_data(it);
         _local_chann_close(c);
      }
   }
}

static void
_local_listen_cb(chann_event_t *e) {
   if (e->event == MNET_EVENT_ACCEPT) {
      tun_local_t *tun = _tun_local();
      if (tun->chann_idx < TUNNEL_CHANN_MAX_COUNT) {
         _local_chann_open(e->r);
      }
      else {
         mnet_chann_close(e->r);
      }
   }
}

/* 
 */

int
tunnel_local_open(tunnel_local_config_t *conf) {
   tun_local_t *tun = _tun_local();
   if (conf && !tun->running) {
      memset(tun, 0, sizeof(*tun));

      tun->conf = *conf;
      tun->active_lst = lst_create();
      tun->free_lst = lst_create();

      tun->tcpin = mnet_chann_open(CHANN_TYPE_STREAM);
      mnet_chann_set_cb(tun->tcpin, _local_listen_cb, tun);
      mnet_chann_listen_ex(tun->tcpin, conf->local_ipaddr, conf->local_port, 1);

      if (conf->mode == TUNNEL_LOCAL_MODE_FRONT) {
         tun->bufout = buf_create(TUNNEL_CHANN_BUF_SIZE);
         tun->buftmp = buf_create(TUNNEL_CHANN_BUF_SIZE);
         assert(tun->bufout && tun->buftmp);
         tun->tcpout = mnet_chann_open(CHANN_TYPE_STREAM);
         mnet_chann_set_cb(tun->tcpout, _local_tcpout_cb_front, tun);
         mnet_chann_set_bufsize(tun->tcpout, 512 * 1024);
         mnet_chann_connect(tun->tcpout, conf->remote_ipaddr, conf->remote_port);
      }

      tun->mode = conf->mode;
      tun->running = 1;

      _info("local open mode %d\n", tun->mode);
      _info("local listen on %s:%d\n", conf->local_ipaddr, conf->local_port);
      _info("\n");

      return 1;
   }
   return 0;
}

void
tunnel_local_close(void) {
   tun_local_t *tun = _tun_local();
   if (tun->running) {
      while (lst_count(tun->active_lst) > 0) {
         tun_local_chann_t *c = (tun_local_chann_t*)lst_popf(tun->active_lst);
         _local_chann_close(c);
      }
      lst_destroy(tun->active_lst);

      if (tun->mode == TUNNEL_LOCAL_MODE_FRONT) {
         buf_destroy(tun->bufout);
         mnet_chann_close(tun->tcpout);
         mnet_chann_set_cb(tun->tcpout, NULL, NULL);
      }
      memset(tun, 0, sizeof(*tun));
      _info("\n");
      _info("local close listen, bye !\n");
      _info("\n");
   }
}

static inline time_t
_local_update_ti() {
   _tun_local()->ti = time(NULL);
   return _tun_local()->ti;
}

static void
_local_send_echo(tun_local_t *tun) {
   unsigned char data[32] = {0};
   u16 data_len = TUNNEL_CMD_CONST_HEADER_LEN + 1;

   memset(data, 0, sizeof(data));

   tunnel_cmd_data_len(data, 1, data_len);
   tunnel_cmd_chann_id(data, 1, 0);
   tunnel_cmd_chann_magic(data, 1, 0);
   tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_ECHO);
   data[data_len - 1] = 1;

   _front_send_remote_data(data, data_len);
   _local_update_ti();

   _verbose("send echo state:%d buffered:%d\n",
            mnet_chann_state(tun->tcpout), buf_buffered(tun->bufout));
}


static void
_local_conf_get_values(tunnel_local_config_t *conf, char *argv[]) {

   conf_t *cf = utils_conf_open(argv[1]);
   if (cf == NULL) {
      _err("fail to get conf from [%s]\n", argv[1]);
      goto fail;
   }

   str_t *value = NULL;

   char dbg_fname[32] = {0};

   value = utils_conf_value(cf, "DEBUG_FILE");
   strncpy(dbg_fname, str_cstr(value), str_len(value));

   value = utils_conf_value(cf, "LOCAL_MODE");
   if (str_cmp(value, "FRONT", 0) == 0) {
      conf->mode = TUNNEL_LOCAL_MODE_FRONT;
   } else {
      goto fail;
   }

   value = utils_conf_value(cf, "LOCAL_IP");
   strncpy(conf->local_ipaddr, str_cstr(value), str_len(value));
   conf->local_port = atoi(str_cstr(utils_conf_value(cf, "LOCAL_PORT")));

   if (conf->mode == TUNNEL_LOCAL_MODE_FRONT) {
      value = utils_conf_value(cf, "REMOTE_IP");
      strncpy(conf->remote_ipaddr, str_cstr(value), str_len(value));
      conf->remote_port = atoi(str_cstr(utils_conf_value(cf, "REMOTE_PORT")));
   }

   value = utils_conf_value(cf, "REMOTE_USERNAME");
   if (value) {
      strncpy(conf->username, str_cstr(value), _MIN_OF(str_len(value), 32));
   }

   value = utils_conf_value(cf, "REMOTE_PASSWORD");
   if (value) {
      strncpy(conf->password, str_cstr(value), _MIN_OF(str_len(value), 32));
   }

   value = utils_conf_value(cf, "CRYPTO_RC4");
   if (value && str_cmp(value, "NO", 0)==0) {
      conf->crypto_rc4 = 0;
   } else {
      conf->crypto_rc4 = 1;
   }

  fail:
   utils_conf_close(cf);

   debug_open(dbg_fname);
   debug_set_option(D_OPT_FILE);
   debug_set_level(D_VERBOSE);
}

int
main(int argc, char *argv[]) {

   if (argc != 2) {
      fprintf(stderr, "[local] %s LOCAL_CONFIG_FILE\n", argv[0]);
      return 0;
   }

#ifndef _WIN32
   signal(SIGPIPE, SIG_IGN);
#endif

   tunnel_local_config_t conf = {TUNNEL_LOCAL_MODE_INVALID,0,0, "", ""};

   _local_conf_get_values(&conf, argv);

   if (conf.mode == TUNNEL_LOCAL_MODE_FRONT)
   {
      mnet_init();

     reset_connection:
      if (tunnel_local_open(&conf) > 0) {
         tun_local_t *tun = _tun_local();

         tun->last_ti = _local_update_ti();
         tun->key = rc4_hash_key(conf.password, strlen(conf.password));

         for (int i=0;;i++) {

            if (i >= TUNNEL_CHANN_MAX_COUNT) {
               i = 0; mtime_sleep(1);
            }

            _local_update_ti();
            mnet_poll( (1<<21) );

            if (tun->mode == TUNNEL_LOCAL_MODE_FRONT) {
               if (tun->ti - tun->last_ti > LOCAL_TIMEOUT_SECOND) {
                  tun->last_ti = tun->ti;

                  if (tun->data_mark <= 0) {
                     _local_send_echo(tun);
                  }
                  tun->data_mark = 0;

                  mm_report(1);
                  _verbose("channs count:%d\n", mnet_report(0));
               }
            }
            else if (tun->reset_connection) {
               tun->reset_connection = 0;
               _info("\n\n\n\n\n local reset connection !!! \n\n\n\n\n");
               goto reset_connection;
            }
         }

          //tunnel_local_close();
      }

      mnet_fini();
   }
   else {
      _err("invalid tunnel mode %d !\n", conf.mode);
   }

   debug_close();
   return 0;
}

#endif
