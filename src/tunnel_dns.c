/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifdef TEST_TUNNEL_DNS

#include <stdio.h>
#include "tunnel_dns.h"
#include "mdns_cnt.h"

#define _err(...) _mlog("dns", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog("dns", D_INFO, __VA_ARGS__)

typedef struct {
   dns_query_callback cb;   
} dns_t;

static inline dns_t* _dns(void) {
   static dns_t g_dns;
   return &g_dns;
}

static void
_dns_query_callback(const unsigned char *ipv4, char *err_msg, void *opaque) {
   dns_t *dns = _dns();
   if (dns->cb) {
      if (ipv4 && !err_msg) {
         unsigned char ipaddr[16] = { 0 };
         int ret = snprintf((char*)ipaddr, 16, "%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3]);
         dns->cb((char*)ipaddr, ret, opaque);
      }
   }
}


/* Public Interfaces 
 */

int
dns_init(dns_query_callback cb) {
   if (cb) {
      _dns()->cb = cb;
      mdns_confg_t conf_list[] = {
         { "8.8.8.8" },            /* google */
         { "8.8.4.4" },            /* google */
         { "" },
      };
      return mdns_init(conf_list, _dns_query_callback);
   }
   return 0;
}

void
dns_fini(void) {
   _dns()->cb = NULL;
   mdns_fini();
}

void
dns_query_domain(const char *domain, int domain_len, void *opaque) {
   if (domain && domain_len>0) {
      mdns_query(domain, domain_len, opaque);
   }
}

void
dns_cleanup_query(int timeout_ms) {
   mdns_cleanup(timeout_ms);
}

#endif
