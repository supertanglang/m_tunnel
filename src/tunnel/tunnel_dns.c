/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#define _GNU_SOURCE
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#endif

#include "m_mem.h"
#include "m_dict.h"
#include "m_stm.h"
#include "m_debug.h"

#include "plat_time.h"
#include "plat_lock.h"
#include "plat_thread.h"

#include "utils_misc.h"
#include "tunnel_dns.h"

#include <assert.h>

#define _err(...) _mlog("dns", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog("dns", D_INFO, __VA_ARGS__)

#ifndef DEF_TUNNEL_DNS_COUNT
#define DEF_TUNNEL_DNS_COUNT 256
#endif

typedef struct {
   char domain[TUNNEL_DNS_DOMAIN_LEN];
   char addr[TUNNEL_DNS_ADDR_LEN];
   int date;
   dns_query_callback cb;
   void *opaque;
} dns_entry_t;

typedef struct {
   int init;
   dict_t *entry_dict;          /* for speed up query, in aux */
   stm_t *domain_stm;
} dns_t;

static void
_domain_stm_finalizer(void *ptr, void *ud) {
   mm_free(ptr);
}

static dns_t* _dns(void) {
   static dns_t g_dns;
   return &g_dns;
}

static int _dns_date() {
   return (int)(mtime_current() >> 20);
}

static dns_entry_t*
_dns_entry_create(const char *domain, int domain_len, const char *addr, int addr_len) {
   dns_t *dns = _dns();
   dns_entry_t *e = (dns_entry_t*)mm_malloc(sizeof(*e));
   strncpy(e->domain, domain, domain_len);
   strncpy(e->addr, addr, _MIN_OF(TUNNEL_DNS_ADDR_LEN, addr_len));
   e->date = _dns_date();
   int ret = dict_set(dns->entry_dict, domain, domain_len, e);
   _err("add dns entry [%s, %s], time:%d ret:%d\n", e->domain, e->addr, e->date, ret);
   return e;
}

static void
_dns_entry_destroy(dns_entry_t *e) {
   dns_t *dns = _dns();
   dict_remove(dns->entry_dict, e->domain, strlen(e->domain));
   mm_free(e);
}

/* description: check valid ip addr */
static int
_valid_ip_addr(const char *addr, int addr_len) {
   int isValid = 1;
   for (int i=0; i<addr_len; i++) {
      if (addr[i]!='.' && (addr[i]<'0' || addr[i]>'9')) {
         isValid = 0;
         break;
      }
   }
   return addr_len<=0 ? 0 : isValid;
}

/* description: query it from DNS server */
static int
_dns_addr_by_name(const char *domain, int domain_len, char *addr, int addr_len) {
   int error = 0;
   struct sockaddr_in sa, *valid_in=NULL;
   struct addrinfo *result=NULL, *curr=NULL;

   sa.sin_family = AF_INET;
   error = getaddrinfo(domain, "http", NULL, &result);
   if (error != 0) {
      _err("Fail to get addr info: [%s] of %s\n", gai_strerror(error));
      goto fail;
   }

   for (curr = result; curr != NULL; curr = curr->ai_next) {
      char ipstr[16] = {0};
      inet_ntop(AF_INET, &(((struct sockaddr_in *)(curr->ai_addr))->sin_addr), ipstr, 16);
      if (strlen(ipstr) > 7) { // '0.0.0.0'
         valid_in = (struct sockaddr_in*)curr->ai_addr;
         memcpy(&sa, valid_in, sizeof(sa));
         break;
      }
   }

   if (valid_in == NULL) {
      _err("Fail to get valid address !\n");
      goto fail;
   }

   error = getnameinfo((struct sockaddr*)&sa, sizeof(sa), addr, addr_len,
                       NULL, 0, NI_NUMERICHOST);
   if (error != 0) {
      _err("Fail to get host name info: %d\n", error);
      goto fail;
   }

  fail:
   if ( result ) {
      freeaddrinfo(result);
   }
   return _valid_ip_addr(addr, strlen(addr));
}

/* description: 2 hour to expire */
static int
_dns_entry_is_expired(dns_entry_t *e) {
   if (e) {
      int date = _dns_date();
      if ((date - e->date) < 7200) {
         return 0;
      }
      _dns_entry_destroy(e);
   }
   return 1;
}

int
_dns_thrd_work_func(void *opaque) {
   dns_t *dns = (dns_t*)opaque;

   if (stm_count(dns->domain_stm) <= 0) {
      mtime_sleep(3);
   }
   else {

      dns_entry_t *oe = (dns_entry_t*)stm_popf(dns->domain_stm);
      int domain_len = strlen(oe->domain);

      if ( _valid_ip_addr(oe->domain, domain_len) ) {
         strncpy(oe->addr, oe->domain, domain_len);
         if (oe->cb) {
            oe->cb(oe->addr, strlen(oe->addr), oe->opaque);
         }
      }
      else {
         dns_entry_t *ne = (dns_entry_t*)dict_get(dns->entry_dict, oe->domain, domain_len);
         if ( !_dns_entry_is_expired(ne) ) {
            strcpy(oe->addr, ne->addr);
            if (oe->cb) {
               oe->cb(oe->addr, strlen(oe->addr), oe->opaque);
            }
         }
         else {
            char dn[TUNNEL_DNS_DOMAIN_LEN] = {0};
            strncpy(dn, oe->domain, _MIN_OF(TUNNEL_DNS_DOMAIN_LEN, domain_len));

            int addr_len = TUNNEL_DNS_ADDR_LEN;
            int found_addr = 0;

            for (int i=0; i<8; i++) {
               int dlen = strlen(dn);

               if (_dns_addr_by_name(dn, dlen, oe->addr, addr_len) > 0) {
                  _dns_entry_create(oe->domain, domain_len, oe->addr, addr_len);
                  found_addr = 1;
                  break;
               }

               strncpy(dn, oe->addr, addr_len);
               memset(oe->addr, 0, addr_len);
            }

            if (oe->cb) {
               if (found_addr) {
                  oe->cb(oe->addr, strlen(oe->addr), oe->opaque);
               }
               else {
                  oe->cb(NULL, 0, oe->opaque);
               }
            }
         }
      }

      _domain_stm_finalizer(oe, NULL);
   }

   return 1;
}

static void
_dict_finalizer(void *opaque, const char *key, int keylen, void *value, int *stop) {
   mm_free(value);
}


/* Public Interfaces 
 */

void
dns_init(void) {
   dns_t *dns = _dns();
   if ( !dns->init ) {
      dns->entry_dict = dict_create(DEF_TUNNEL_DNS_COUNT, 0, NULL);
      dns->domain_stm = stm_create("dns_domain_cache", _domain_stm_finalizer, NULL);

      mthrd_init(MTHRD_MODE_POWER_HIGH);
      mthrd_suspend(MTHRD_MAIN); /* suspend forever */
      mthrd_after(MTHRD_AUX, _dns_thrd_work_func, _dns(), 0);
      dns->init = 1;
   }
}

void
dns_fini(void) {
   dns_t *dns = _dns();
   if ( dns->init ) {
      mthrd_fini();
      dict_destroy(dns->entry_dict, _dict_finalizer, NULL);
      dns->init = 0;
   }
}


void
dns_query_domain(const char *domain, int domain_len, dns_query_callback cb, void *opaque) {
   if (domain && domain_len>0 && cb) {
      dns_t *dns = _dns();
      dns_entry_t *e = (dns_entry_t*)mm_malloc(sizeof(*e));

      strncpy(e->domain, domain, _MIN_OF(domain_len, TUNNEL_DNS_DOMAIN_LEN));
      e->date = _dns_date();
      e->cb = cb;
      e->opaque = opaque;

      stm_pushl(dns->domain_stm, e);
   }
}
