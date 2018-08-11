/* 
 * Copyright (c) 2018 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef MDNS_CNT_H
#define MDNS_CNT_H

//#define MDNS_CLIENT_STANDALONE_MODE /*  as standalone */
#define MDNS_QUERY_DOMAIN_LEN  256
#define MDNS_IP_EXPIRED_SECOND 172800 /* 2 day, 3600*24*2 */

typedef struct {
   char dns_ipv4[16];             /* IPv4 */
} mdns_confg_t;

#ifdef __cplusplus
extern "C" {
#endif

/* ip is 4 byte data */
typedef void (*mdns_query_callback)(const unsigned char *ipv4, char *err_msg, void *opaque);

// terminate with dns_ipv4[0] == 0
int mdns_init(mdns_confg_t *confg_list, mdns_query_callback cb);
int mdns_query(const char *domain, int domain_len, void *opaque);
void mdns_cleanup(int timeout_ms);
void mdns_fini(void);

#ifdef __cplusplus
}
#endif

#endif
