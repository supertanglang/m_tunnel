/* 
 * Copyright (c) 2017 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "m_debug.h"
#include "m_md5.h"

#include "utils_args.h"
#include "utils_str.h"

#include "mnet_core.h"
#include "tunnel_conf.h"

static int
_get_md5_value(const char *value, char *result) {
   if (value) {
      char input[64] = { 0 };
      int min = _min_of(strlen(value), 32);
      int i = sprintf(input, "%s", "9$T%z4Ph");
      strncpy(&input[i], value, min);
      i += min;
      {
         MD5_CTX ctx;
         MD5_Init(&ctx);
         MD5_Update(&ctx, input, i);
         MD5_Final((unsigned char*)result, &ctx);
      }
      return 1;
   }
   return 0;
}

int
tunnel_conf_get_values(tunnel_config_t *conf, int argc, char *argv[]) {
   int ret = 0;

   if (conf==NULL || argc<=1 || argv==NULL) {
      fprintf(stderr, "invalid params !\n");
      return ret;
   }
   memset(conf, 0, sizeof(*conf));

   args_t *ag = utils_args_open(argc, (const char**)argv);
   if (ag == NULL) {
      fprintf(stderr,
              "-dbg output file name, default stdout\n");
      goto fail;
   }


   // debug output file name
   const char *value = utils_args_string(ag, "-debug");
   if (value) {
      strncpy(conf->dbg_fname, value, 16);
   } else {
      strncpy(conf->dbg_fname, "stdout", 5);
   }


   chann_addr_t addr;

   // local
   value = utils_args_string(ag, "-l");
   if (value && mnet_parse_ipport(value, &addr)) {
      strncpy(conf->local_ipaddr, addr.ip, 16);
      conf->local_port = addr.port;
   } else {
      fprintf(stderr, "fail to local ip !\n");
      goto fail;
   }


   // remote
   value = utils_args_string(ag, "-r");
   if (value && mnet_parse_ipport(value, &addr)) {
      strncpy(conf->remote_ipaddr, addr.ip, 16);
      conf->remote_port = addr.port;
   } else {
      fprintf(stderr, "fail to remote ip !\n");
      goto fail;
   }



   // username
   value = utils_args_string(ag, "-u");
   if (value) {
      _get_md5_value(value, conf->username);
   }

   // password
   value = utils_args_string(ag, "-p");
   if (value) {
      _get_md5_value(value, conf->password);
   }


   ret = 1;


   // rc4 switch
   value = utils_args_string(ag, "-rc4");
   if (value && strncmp(value, "no", 2)==0) {
      conf->crypto_rc4 = 0;
   } else {
      conf->crypto_rc4 = 1;
   }

   //
   conf->power_save = utils_args_integer(ag, "-power_save");
   if (conf->power_save == 0x7fffffff) {
      conf->power_save = 10;
   }

  fail:
   utils_args_close(ag);

   if (ret <= 0) {
      fprintf(stderr, "fail to parse config !\n");
   } else {
      printf("%s, %s:%d, %s:%d, %s:%s, %d:%d\n", conf->dbg_fname, conf->local_ipaddr, conf->local_port,
             conf->remote_ipaddr, conf->remote_port, conf->username, conf->password, conf->crypto_rc4, 
             conf->power_save);
   }

   return ret;
}


void
_hex_addr(char *addr, int addr_len, unsigned char *e, int elen) {
   str_t *head = str_clone_cstr(addr, addr_len);
   str_t *sp = str_split(head, ".", 0);
   int i = 0;
   str_foreach(s, sp) {
      e[i++] = atoi(str_cstr(s));
   }
   str_destroy(head);
}
