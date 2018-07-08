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
#include "plat_os.h"

#if defined(PLAT_OS_WIN)

#include <io.h>
#include <process.h>
#include <time.h>

#else

#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>

#endif

#include "plat_type.h"
#include "plat_time.h"

#include "m_mem.h"
#include "m_buf.h"
#include "m_list.h"
#include "m_rc4.h"
#include "m_chacha20.h"
#include "m_timer.h"
#include "m_sha256.h"
#include "utils_debug.h"

#include "mnet_core.h"

#include "tunnel_cmd.h"
#include "tunnel_dns.h"
#include "tunnel_conf.h"
#include "tunnel_compress.h"

#include <assert.h>

#define _err(...) _mlog(0, "local", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog(0, "local", D_INFO, __VA_ARGS__)
#define _verbose(...) _mlog(0, "local", D_VERBOSE, __VA_ARGS__)

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
   int data_mark;               /* data mark */
} tun_local_chann_t;

typedef struct {
   int running;                 /* running status */
   time_t ti;
   uint64_t key;
   int data_mark;
   u16 chann_idx;
   u16 magic_code;
   local_front_state_t state;
   tunnel_config_t conf;
   unsigned char crypt_salt[SHA256_HASH_BYTES]; /* salt from server */
   chann_t *tcpin;               /* tcp for listen */
   chann_t *tcpout;              /* tcp for forward */
   buf_t *bufout;                /* buf for forward */
   buf_t *buf_rc4;               /* buf for crypto */
   buf_t *buf_flz;               /* buf for fastlz */
   lst_t *active_lst;            /* active chann list */
   lst_t *free_lst;              /* free chann list */
   uint64_t rcv_comp;            /* bytes compressed */
   uint64_t snd_comp;            /* bytes compressed */
   chacha20_ctx_t enc;
   chacha20_ctx_t dec;
   tun_local_chann_t *channs[TUNNEL_CHANN_MAX_COUNT];
} tun_local_t;

static void _local_chann_tcpin_cb_front(chann_msg_t *e);
static void _local_tcpout_cb_front(chann_msg_t *e);
void tunnel_local_close(void);

static inline tun_local_t* _tun_local(void) {
   static tun_local_t _g_local;
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
      c->chann_id = tun->chann_idx;
      tun->chann_idx += 1;
   }
   c->bufin = buf_create(TUNNEL_CHANN_DATA_SIZE);
   assert(c->bufin);

   tun->channs[c->chann_id] = c;
   c->magic = (++tun->magic_code);
   c->tcpin = r;
   c->node = lst_pushl(tun->active_lst ,c);
   buf_reset(c->bufin);

   c->state = LOCAL_CHANN_STATE_WAIT_LOCAL; /* wait local connect cmd */
   mnet_chann_set_cb(c->tcpin, _local_chann_tcpin_cb_front, c);
}

/* description: free local resources
 */
static void
_local_chann_close(tun_local_chann_t *c, int line) {
   tun_local_t *tun = _tun_local();
   if (c->node) {
      _verbose("(%d) chann %p %u:%u close, state:%d (a:%d,f:%d)\n", line,
               c->tcpin, c->chann_id, c->magic, mnet_chann_state(c->tcpin),
               lst_count(tun->active_lst), lst_count(tun->free_lst));

      tun->channs[c->chann_id] = NULL;
      buf_destroy(c->bufin);

      lst_remove(tun->active_lst, c->node);
      lst_pushl(tun->free_lst, c);

      c->bufin = NULL;
      c->node = NULL;
      c->state = LOCAL_CHANN_STATE_NONE;

      mnet_chann_disconnect(c->tcpin);
      mnet_chann_close(c->tcpin);
   }
}

static int
_hex_equal(uint8_t *s, int slen, uint8_t *e, int elen) {
   int mlen = _min_of(slen, elen);

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

   mnet_chann_send(c->tcpin, es, 10);
   c->state = LOCAL_CHANN_STATE_CONNECTED;
}

static int
_front_send_remote_data(unsigned char *buf, u16 buf_len) {
   tun_local_t *tun = _tun_local();

   if (tun->conf.crypto_rc4) {
      u8 *rbuf = (u8*)buf_addr(tun->buf_rc4, 0);
      const int base = TUNNEL_CMD_CONST_DATA_LEN_OFFSET;

      chacha20_xor(&tun->enc, &buf[base], &rbuf[base], buf_len - base);
      
      tunnel_cmd_data_len(rbuf, 1, buf_len);
      return mnet_chann_send(tun->tcpout, rbuf, buf_len);
   }
   else {
      return mnet_chann_send(tun->tcpout, buf, buf_len);
   }
   return 0;
}

static int
_front_recv_remote_data(buf_t *b) {
   tun_local_t *tun = _tun_local();

   u8 *buf = (u8*)buf_addr(b,0);
   int buf_len = buf_buffered(b);

   if (tun->conf.crypto_rc4) {
      u8 *rbuf = (u8*)buf_addr(tun->buf_rc4, 0);
      const int base = TUNNEL_CMD_CONST_DATA_LEN_OFFSET;

      chacha20_xor(&tun->dec, &buf[base], &rbuf[base], buf_len - base);
      
      buf = rbuf;
      tunnel_cmd_data_len(buf, 1, buf_len);
   }

   if (tunnel_cmd_head_cmd(buf, 0, 0) == TUNNEL_CMD_DATA_COMPRESSED) {
      const int hlen = TUNNEL_CMD_CONST_HEADER_LEN;

      uint8_t *fbuf = (uint8_t*)buf_addr(tun->buf_flz, 0);
      int flen = tun_decompress(&buf[hlen], buf_len-hlen,
                                &fbuf[hlen], buf_len(tun->buf_flz)-hlen);

      memcpy(fbuf, buf, hlen);
      tun->rcv_comp += (flen + hlen - buf_len);

      buf = fbuf;
      buf_len = hlen + flen;

      tunnel_cmd_data_len(buf, 1, buf_len);
      tunnel_cmd_head_cmd(buf, 1, TUNNEL_CMD_DATA_RAW);
   }

   if (buf != (u8*)buf_addr(b,0)) {
      memcpy(buf_addr(b,0), buf, buf_len);
      buf_reset(b);
      buf_forward_ptw(b, buf_len);
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
   return (buf_available(b) - RC4_CRYPTO_OCCUPY); /* keep space for RC4 crypto */
}

static inline char*
_fix_string_1024(char *p, int len) {
   static char buf[1024];
   for (int i=0; i<len; i++) {
      buf[i] = p[i];
   }
   buf[len] = 0;
   return buf;
}


void
_local_chann_tcpin_cb_front(chann_msg_t *e) {
   tun_local_t *tun = _tun_local();
   tun_local_chann_t *fc = (tun_local_chann_t*)e->opaque;

   if (e->event == CHANN_EVENT_RECV)
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

         // try compress data with fastlz
         const int fastlz = tun->conf.fastlz;
         if (fastlz && data_len>(hlen+TUNNEL_CHANN_FASTLZ_MIN_LEN)) {
            uint8_t *fbuf = buf_addr(tun->buf_flz, 0);
            int flen = tun_compress(fastlz, &data[hlen], data_len-hlen, &fbuf[hlen]);

            if (flen < data_len-hlen) {
               tun->snd_comp += (data_len - hlen - flen);

               data = fbuf;
               data_len = hlen + flen;

               tunnel_cmd_data_len(data, 1, data_len);
               tunnel_cmd_chann_id(data, 1, fc->chann_id);
               tunnel_cmd_chann_magic(data, 1, fc->magic);
               tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_DATA_COMPRESSED);
            }
         }

         if (data == buf_addr(ib,0)) {
            tunnel_cmd_data_len(data, 1, data_len);
            tunnel_cmd_chann_id(data, 1, fc->chann_id);
            tunnel_cmd_chann_magic(data, 1, fc->magic);
            tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_DATA_RAW);
         }

         fc->data_mark += !!data_len;
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
            return;
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
                  _verbose("(in) chann %u:%u try connect [%s:%d]\n", fc->chann_id, fc->magic,
                           _fix_string_1024(domain, dlen), port);

                  strncpy(addr, domain, dlen);
                  _front_cmd_connect(fc, TUNNEL_ADDR_TYPE_DOMAIN, addr, port);
               }
            }
         }
      }

      buf_reset(ib);
   }
   else if (e->event == CHANN_EVENT_DISCONNECT)
   {
      _verbose("(in) chann %u:%u close, mnet\n", fc->chann_id, fc->magic);
      _front_cmd_close(fc);
      _local_chann_close(fc, __LINE__);
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
_local_tcpout_cb_front(chann_msg_t *e) {
   tun_local_t *tun = _tun_local();
   
   if (e->event == CHANN_EVENT_RECV) {
      tunnel_cmd_t tcmd = {0, 0, 0, 0, NULL};

      for (;;) {
         int ret = 0;
         buf_t *ob = tun->bufout;

         if (buf_buffered(ob) < TUNNEL_CMD_CONST_HEADER_LEN) {
            ret = mnet_chann_recv(e->n, buf_addr(ob,buf_ptw(ob)), TUNNEL_CMD_CONST_HEADER_LEN - buf_buffered(ob));
         } else {
            tunnel_cmd_check(ob, &tcmd);
            if (tcmd.data_len > TUNNEL_CHANN_BUF_SIZE + 8) {
               _err("(out) invalid data size %d!\n", tcmd.data_len);
               break;
            }
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
            _err("(out) fail to decode !\n");
            goto reset_buffer;
         }

         tunnel_cmd_check(ob, &tcmd);
         if (tcmd.cmd<=TUNNEL_CMD_NONE || tcmd.cmd>TUNNEL_CMD_DATA_COMPRESSED) {
            _err("(out) invalid cmd !\n");
            goto reset_buffer;
         }

         tun->data_mark++;

         if (tcmd.cmd == TUNNEL_CMD_ECHO) {
            _verbose("(out) receive echo\n");
            goto reset_buffer;
         }

         if (tun->state == LOCAL_FRONT_STATE_AUTHORIZED) {
         
            tun_local_chann_t *fc = _local_chann_of_cmd(tun, &tcmd);

            if (fc) {
               if (tcmd.cmd == TUNNEL_CMD_DATA_RAW)
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
                  _local_chann_close(fc, __LINE__);
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
                  _info("(out) got authority value %d\n", tcmd.payload[0]);
               }
            }
         }
         else {
            _err("invalid tun state !\n");
         }
        reset_buffer:
         buf_reset(ob);
      }
   }
   else if (e->event == CHANN_EVENT_CONNECTED) {
      
      /* get salt from server */
      int ret = 0;
      do {
         mtime_sleep(1);
         ret += mnet_chann_recv(e->n, tun->crypt_salt, SHA256_HASH_BYTES - ret);
         //_print_hex(tun->crypt_salt, 32);
      } while (ret < SHA256_HASH_BYTES);

      
      /* prepare auth data */
      unsigned char data[64] = {0};
      memset(data, 0, sizeof(data));

      int head_len = TUNNEL_CMD_CONST_HEADER_LEN;
      u16 data_len = head_len + 1 + 2 * SHA256_HASH_BYTES;

      tunnel_cmd_data_len(data, 1, data_len);
      tunnel_cmd_chann_id(data, 1, 0);
      tunnel_cmd_chann_magic(data, 1, 0);
      tunnel_cmd_head_cmd(data, 1, TUNNEL_CMD_AUTH);

      data[head_len] = 1;       /* auth type */

      int uname_base = head_len + 1; /* user name */
      _sha256_salt(tun->conf.username, tun->crypt_salt, &data[uname_base]);

      int passw_base = uname_base + SHA256_HASH_BYTES; /* user password */
      _sha256_salt(tun->conf.password, tun->crypt_salt, &data[passw_base]);

      _front_send_remote_data(data, data_len);

      _verbose("(out) connected, send auth request\n");
      tun->state = LOCAL_FRONT_STATE_CONNECTED;
   }
   else if (e->event == CHANN_EVENT_DISCONNECT)
   {
      _verbose("(out) chann close\n");
      tun->state = LOCAL_FRONT_STATE_NONE;
      lst_foreach(it, tun->active_lst) {
         tun_local_chann_t *c = (tun_local_chann_t*)lst_iter_data(it);
         _local_chann_close(c, __LINE__);
      }
   }
}

static void
_local_listen_cb(chann_msg_t *e) {
   if (e->event == CHANN_EVENT_ACCEPT) {
      tun_local_t *tun = _tun_local();
      if (tun->state == LOCAL_FRONT_STATE_AUTHORIZED &&
          tun->chann_idx < TUNNEL_CHANN_MAX_COUNT)
      {
         _local_chann_open(e->r);
      } else {
         mnet_chann_close(e->r);
      }
   }
}

int
tunnel_local_open(tunnel_config_t *conf) {
   tun_local_t *tun = _tun_local();
   if (conf && !tun->running) {
      memset(tun, 0, sizeof(*tun));

      tun->conf = *conf;
      tun->active_lst = lst_create();
      tun->free_lst = lst_create();

      tun->tcpin = mnet_chann_open(CHANN_TYPE_STREAM);
      mnet_chann_set_cb(tun->tcpin, _local_listen_cb, tun);
      mnet_chann_listen(tun->tcpin, conf->local_ipaddr, conf->local_port, 1);

      tun->bufout = buf_create(TUNNEL_CHANN_BUF_SIZE);
      tun->buf_rc4 = buf_create(TUNNEL_CHANN_BUF_SIZE);
      tun->buf_flz = buf_create(TUNNEL_CHANN_BUF_SIZE);

      assert(tun->bufout && tun->buf_rc4 && tun->buf_flz);

      tun->tcpout = mnet_chann_open(CHANN_TYPE_STREAM);
      mnet_chann_set_bufsize(tun->tcpout, 131072);
      mnet_chann_set_cb(tun->tcpout, _local_tcpout_cb_front, tun);
      mnet_chann_connect(tun->tcpout, conf->remote_ipaddr, conf->remote_port);

      tun->running = 1;

      _info("local listen on %s:%d\n", conf->local_ipaddr, conf->local_port);
      _info("\n");
      return 1;
   }
   return 0;
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

   _verbose("send echo state:%d buffered:%d\n",
            mnet_chann_state(tun->tcpout), buf_buffered(tun->bufout));
}

static void
_local_tmr_callback(tmr_timer_t *tm, void *opaque) {
   tun_local_t *tun = (tun_local_t*)opaque;

   if (tun->data_mark <= 0) {
      _local_send_echo(tun);
   }
   tun->data_mark = 0;

   lst_foreach(it, tun->active_lst) {
      tun_local_chann_t *fc = (tun_local_chann_t*)lst_iter_data(it);
      if (fc->data_mark > 0) {
         fc->data_mark = 0;
      } else {
         _verbose("(tmr) chann %u:%u close, mnet\n", fc->chann_id, fc->magic);         
         _front_cmd_close(fc);
         _local_chann_close(fc, __LINE__);
      }
   }

   uint64_t rcv_all = mnet_chann_bytes(tun->tcpout, 0);
   uint64_t snd_all = mnet_chann_bytes(tun->tcpout, 1);

   mm_report(1);
   _info("channs count:%d, rcv:%.3fMb, snd:%.3fMb, comp:%.2f\n",
         mnet_report(0),
         ((double)mnet_chann_bytes(tun->tcpout, 0))/1048576.0,
         ((double)mnet_chann_bytes(tun->tcpout, 1))/1048576.0,
         ((double)(tun->rcv_comp + tun->snd_comp)) / (double)(rcv_all + snd_all));
}

static inline time_t
_local_update_ti() {
   _tun_local()->ti = time(NULL);
   return _tun_local()->ti;
}

int
main(int argc, char *argv[]) {
   tunnel_config_t conf;

   if ( !tunnel_conf_get_values(&conf, argc, argv) ) {
      return 0;
   }

   debug_init(1);
   debug_open(0, conf.dbg_fname);
   debug_set_option(0, D_OPT_FILE);
   debug_set_level(0, D_INFO);

   mnet_init();

   if (tunnel_local_open(&conf) > 0) {
      tun_local_t *tun = _tun_local();
      tmr_t *tmr = tmr_create_lst();

      _local_update_ti();
      tmr_add(tmr, tun->ti, 30, 1, tun, _local_tmr_callback);

      tun->key = _init_hash_key(&conf);

      /* chacha20 */
      chacha20_ctx_init(&tun->enc);
      chacha20_key_setup(&tun->enc, "01234567890123456789012345678901", 32);
      chacha20_iv_setup(&tun->enc, "01234567", 8);

      chacha20_ctx_init(&tun->dec);
      chacha20_key_setup(&tun->dec, "01234567890123456789012345678901", 32);
      chacha20_iv_setup(&tun->dec, "01234567", 8);
      

      for (int i=0;;i++) {

         if (i >= TUNNEL_CHANN_MAX_COUNT) {
            i=0; mtime_sleep(1);
         }

         _local_update_ti();
         
         mnet_poll( 2000000 );

         tmr_update_lst(tmr, tun->ti);
      }

      tmr_destroy_lst(tmr);
   }

   mnet_fini();
   debug_close(0);
   debug_fini();
   return 0;
}

#endif  /* TEST_TUNNEL_LOCAL */
