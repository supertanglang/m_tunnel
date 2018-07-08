/* 
 * Copyright (c) 2017 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#define  _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils_debug.h"
#include "utils_args.h"
#include "utils_str.h"

#include "mnet_core.h"
#include "tunnel_conf.h"

int
tunnel_conf_get_values(tunnel_config_t *conf, int argc, char *argv[]) {
   int ret = 0;
   args_t *ag = NULL;

   if (conf==NULL || argc<=1 || argv==NULL || (ag = utils_args_open(argc, (const char**)argv))==NULL) {
      fprintf(stderr, "tun: fail to parse option !\n");
      goto fail;
   }
   memset(conf, 0, sizeof(*conf));


   // debug output file name
   const char *value = utils_args_string(ag, "-d");
   if (value) {
      strncpy(conf->dbg_fname, value, 16);
   } else {
      strncpy(conf->dbg_fname, "stdout", 6);
   }


   chann_addr_t addr;

   // local
   value = utils_args_string(ag, "-l");
   if (value && mnet_parse_ipport(value, &addr)) {
      strncpy(conf->local_ipaddr, addr.ip, 16);
      conf->local_port = addr.port;
   }


   // remote
   value = utils_args_string(ag, "-r");
   if (value && mnet_parse_ipport(value, &addr)) {
      strncpy(conf->remote_ipaddr, addr.ip, 16);
      conf->remote_port = addr.port;
   }

   if (strlen(conf->local_ipaddr)<=0 && strlen(conf->remote_ipaddr)<=0) {
      fprintf(stderr, "tun: fail to parse addr !\n");
      goto fail;
   }



   // username
   value = utils_args_string(ag, "-u");
   if (value) {
      strncpy(conf->username, value, SHA256_HASH_BYTES);
   } else {
      fprintf(stderr, "tun: fail to parse username !\n");
      goto fail;      
   }

   // password
   value = utils_args_string(ag, "-p");
   if (value) {
      strncpy(conf->password, value, SHA256_HASH_BYTES);
   } else {
      fprintf(stderr, "tun: fail to parse password !\n");
      goto fail;      
   }

   // chacha20 switch
   value = utils_args_string(ag, "-crypto");
   if (value && strncmp(value, "0", 1)==0) {
      conf->crypto = 0;
   } else {
      conf->crypto = 1;
   }

   // fastlz
   value = utils_args_string(ag, "-compress");
   if (value && strncmp(value, "0", 1)==0) {
      conf->compress = 0;         /* disable */
   } else if (value && strncmp(value, "1", 1)==0) {
      conf->compress = 1;         /* level 1 */
   } else {
      conf->compress = 2;         /* level 2 */
   }


   ret = 1;



  fail:
   utils_args_close(ag);

   if (ret <= 0) {
      struct s_error {
         char *string;
      };
      struct s_error err[] = {
         { " -l \t local ipport, '127.0.0.1:1234'" },
         { " -r \t remote ipport" },
         { " -u \t username (256bits)" },
         { " -p \t password (256bits)" },
         { " -d \t debug output file, default 'stdout'" },
         { " -crypto \t default '1', '0' to disable" },
         { " -compress \t default '2', '0' to disable" },
         { NULL },
      };
      fprintf(stderr, "usage: %s [options]\nAvailable options are:\n", argv[0]);
      for (int i=0; err[i].string; i++) {
         fprintf(stderr, "%s\n", err[i].string);
      }
   } else {
      printf("tun: %s, local->%s:%d, remote->%s:%d, crypto->%d, compress->%d\n",
             conf->dbg_fname,
             conf->local_ipaddr, conf->local_port,
             conf->remote_ipaddr, conf->remote_port,
             conf->crypto, conf->compress);
   }

   return ret;
}


/* helper
 */

void
_init_hash_key(chacha20_ctx_t *ctx, tunnel_config_t *conf) {
   chacha20_ctx_init(ctx);
   chacha20_key_setup(ctx, conf->password, SHA256_HASH_BYTES);
   chacha20_iv_setup(ctx, conf->username, 8);
}

/* assume all SHA256_HASH_BYTES */
void
_sha256_salt(void *data, void *salt, void *hash) {
   unsigned char buf[SHA256_HASH_BYTES + SHA256_HASH_BYTES];
   memcpy(buf, data, SHA256_HASH_BYTES);
   memcpy(&buf[SHA256_HASH_BYTES], salt, SHA256_HASH_BYTES);
   sha256_once((const void*)buf, (size_t)(2*SHA256_HASH_BYTES), hash);
}

void
_binary_addr(char *addr, int addr_len, unsigned char *e, int elen) {
   str_t *head = str_clone_cstr(addr, addr_len);
   str_t *sp = str_split(head, ".", 0);
   int i = 0;
   str_foreach(s, sp) {
      e[i++] = atoi(str_cstr(s));
   }
   str_destroy(head);
}

void
_print_hex(unsigned char *buf, int len) {
   for (int i=0; i<len; i++) {
      if (i && i%15==0) {
         printf("\n");
      }
      printf("%02x ", buf[i]);      
   }
   printf("\n");
}
