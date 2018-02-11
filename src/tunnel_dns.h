/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _TUNNEL_DNS_H
#define _TUNNEL_DNS_H

#define TUNNEL_DNS_ADDR_LEN (16)
#define TUNNEL_DNS_DOMAIN_LEN (378)

void dns_init(void);
void dns_fini(void);

/* return addr==NLL means can not find */
typedef void(*dns_query_callback)(char *addr, int addr_len, void *opaque);

void dns_query_domain(
   const char *domain, int domain_len, dns_query_callback cb, void *opaque);


#endif
