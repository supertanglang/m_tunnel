/* 
 * Copyright (c) 2017 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TUNNEL_CONF_H
#define TUNNEL_CONF_H

typedef struct {
   char dbg_fname[32];
   int local_port;
   int remote_port;
   char local_ipaddr[16];
   char remote_ipaddr[16];
   char username[32];
   char password[32];
   int crypto_rc4;              /* 0 to disble, default enable */
   int power_save;              /* 0 is highest */
} tunnel_config_t;

static inline int _min_of(int a, int b) {
   return a < b ? a : b;
}

void _binary_addr(char *addr, int addr_len, unsigned char *e, int elen);

int tunnel_conf_get_values(tunnel_config_t *conf, int argc, char *argv[]);

#endif
