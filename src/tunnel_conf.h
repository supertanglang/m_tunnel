/* 
 * Copyright (c) 2017 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TUNNEL_CONF_H
#define TUNNEL_CONF_H

#include "m_sha256.h"
#include "m_chacha20.h"

typedef struct {
   char dbg_fname[32];
   int local_port;
   int remote_port;
   char local_ipaddr[16];
   char remote_ipaddr[16];
   char username[SHA256_HASH_BYTES];
   char password[SHA256_HASH_BYTES];
   int crypto;                  /* 0 to disable, default 1 */
   int compress;                /* 0 to disable, default 2 */
} tunnel_config_t;

static inline int _min_of(int a, int b) {
   return a < b ? a : b;
}

int tunnel_conf_get_values(tunnel_config_t *conf, int argc, char *argv[]);

/* helper
 */

void _init_hash_key(chacha20_ctx_t*, tunnel_config_t*);

void _sha256_salt(void *data, void *salt, void *hash);

void _binary_addr(char *addr, int addr_len, unsigned char *e, int elen);

void _print_hex(unsigned char *buf, int len);

#endif
