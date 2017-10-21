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

#include "utils_conf.h"
#include "utils_misc.h"

#include "tunnel_conf.h"

static int
_get_ip_port(str_t *value, char *ip, int *port) {
   int pos = 0;
   if (value && (pos = str_locate(value, ":", 0))>0) {
      str_t *sub = str_sub(value, 0, pos);
      strncpy(ip, str_cstr(sub), str_len(sub));
      *port = atoi(str_cstr(str_sub(value, pos + 1, str_len(value))));
      return 1;
   }
   return 0;
}

static int
_get_md5_value(const char *value, int vlen, char *result) {
   if (value && vlen > 0 && vlen<=32) {
      char input[64];
      memset(input, 0, 64);
      strncpy(input, value, vlen);
      strncpy(&input[vlen], "9$T%z4Ph", 8); /* add salt */
      vlen += 8;
      {
         MD5_CTX ctx;
         MD5_Init(&ctx);
         MD5_Update(&ctx, value, vlen);
         MD5_Final((unsigned char*)result, &ctx);
      }
      return 1;
   }
   return 0;
}

int
tunnel_conf_get_values(tunnel_config_t *conf, char *argv[]) {
   int ret = 0;

   if (conf==NULL || argv==NULL) {
      fprintf(stderr, "invalid params !\n");
      return ret;
   }
   memset(conf, 0, sizeof(*conf));

   conf_t *cf = utils_conf_open(argv[1]);
   if (cf == NULL) {
      fprintf(stderr, "fail to open config !\n");
      goto fail;
   }

   str_t *value = NULL;
   strncpy(conf->dbg_fname, "stdout", 5);

   value = utils_conf_value(cf, "DEBUG_FILE");
   if (value && str_len(value)<32) {
      strncpy(conf->dbg_fname, str_cstr(value), str_len(value));
   }

   value = utils_conf_value(cf, "LOCAL_ADDR");
   if (value && !_get_ip_port(value, conf->local_ipaddr, &conf->local_port) ) {
      fprintf(stderr, "fail to ip !\n");
      goto fail;
   }

   value = utils_conf_value(cf, "REMOTE_ADDR");
   if ( !_get_ip_port(value, conf->remote_ipaddr, &conf->remote_port) ) {
      goto fail;
   }

   value = utils_conf_value(cf, "USER_NAME");
   if (value) {
      _get_md5_value((const char*)str_cstr(value), _MIN_OF(str_len(value), 32), conf->username);
   }

   value = utils_conf_value(cf, "PASS_WORD");
   if (value) {
      _get_md5_value((const char*)str_cstr(value), _MIN_OF(str_len(value),32), conf->password);
   }

   ret = 1;

   value = utils_conf_value(cf, "CRYPTO_RC4");
   if (value && str_cmp(value, "NO", 0)==0) {
      conf->crypto_rc4 = 0;
   } else {
      conf->crypto_rc4 = 1;
   }

   value = utils_conf_value(cf, "POWER_SAVE");
   if (value) {
      conf->power_save = atoi(str_cstr(value));
   }

  fail:
   utils_conf_close(cf);

   if (ret <= 0) {
      fprintf(stderr, "fail to parse config !\n");
   } else {
      printf("%s, %s:%d, %s:%d, %s:%s, %d:%d\n", conf->dbg_fname, conf->local_ipaddr, conf->local_port,
             conf->remote_ipaddr, conf->remote_port, conf->username, conf->password, conf->crypto_rc4, 
             conf->power_save);
   }

   return ret;
}
