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
   char username[64];
   char password[64];
   int crypto_rc4;              /* 0 to disble, default enable */
   int power_save;              /* 0 is highest */
} tunnel_config_t;

int tunnel_conf_get_values(tunnel_config_t *conf, char *argv[]);

#endif
