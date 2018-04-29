/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _TUNNEL_DNS_H
#define _TUNNEL_DNS_H

#define TUNNEL_DNS_ADDR_LEN (16)
#define TUNNEL_DNS_DOMAIN_LEN (256)

#ifdef __cplusplus
extern "C" {
#endif

// return addr==NLL means can not find
typedef void(*dns_query_callback)(char *addr, int addr_len, void *opaque);

// init after mnet_init()
int dns_init(dns_query_callback cb);
void dns_fini(void);

void dns_query_domain(const char *domain, int domain_len, void *opaque);
void dns_cleanup_query(int timeout_ms);

#ifdef __cplusplus
}
#endif


#endif
