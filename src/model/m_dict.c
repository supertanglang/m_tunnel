/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#define _CRT_SECURE_NO_WARNINGS

#include <string.h>
#include <assert.h>

#include "m_dict.h"
#include "m_list.h"
#include "m_mem.h"

typedef struct s_dict_kv {
   struct s_dict_kv *next;
   lst_node_t *node;            /* node of list */
   uint32_t hash;
   void *value;
   int keylen;
   char *key;
} dict_kv_t;

struct s_dict {
   int count;
   int capacity;
   float factor;
   dict_key_hash_callback hash_cb;
   lst_t *kv_lst;
   dict_kv_t **kv_cache;
};

dict_t*
dict_create(int capacity_init, float expand_factor, dict_key_hash_callback cb) {
   dict_t *d = (dict_t*)mm_malloc(sizeof(dict_t));
   if (d) {
      d->capacity = capacity_init>0 ? capacity_init : 4;
      if (expand_factor>0 && expand_factor<1.0) {
         d->factor = expand_factor;
      } else {
         d->factor = 0.75;
      }
      d->hash_cb = cb ? cb : dict_default_key_hash;
      d->kv_cache = (dict_kv_t**)mm_malloc(capacity_init * sizeof(dict_kv_t*));
      d->kv_lst = lst_create();
      return d;
   }
   return NULL;
}

void
dict_destroy(dict_t *d) {
   if (d) {
      while (lst_count(d->kv_lst)) {
         mm_free(lst_popf(d->kv_lst));
      }
      lst_destroy(d->kv_lst);
      mm_free(d->kv_cache);
      mm_free(d);
   }
}

int
dict_count(dict_t *d) {
   if (d) {
      return d->count;
   }
   return -1;
}

uint32_t
dict_default_key_hash(const char *key, int keylen) {
   uint32_t h = (uint32_t)keylen;
   for (int i=0; i<keylen; i++) {
      h = h ^ ((h<<5)+(h>>2)+(uint32_t)key[i]);
   }
   return h;
}

static dict_kv_t*
_dict_get_kv(dict_t *d, const char *key, int keylen, uint32_t *out_hash) {
   uint32_t hash = d->hash_cb(key, keylen);
   dict_kv_t *kv = d->kv_cache[hash % d->capacity];

   if (out_hash) {
      *out_hash = hash;
   }

   while (kv) {
      if ((kv->hash==hash) && (kv->keylen==keylen) && (strncmp(kv->key, key, keylen)==0)) {
         return kv;
      }
      kv = kv->next;
   }
   return NULL;
}

static void
_dict_update_index(dict_t *d, dict_kv_t *kv) {
   uint32_t h = kv->hash % d->capacity;
   kv->next = d->kv_cache[h];
   d->kv_cache[h] = kv;
}

static int
_dict_expand(dict_t *d) {
   if (d->count >= (int)(d->capacity * d->factor)) {
      int capacity = d->capacity << 1;
      dict_kv_t **kv_cache = (dict_kv_t**)mm_realloc(d->kv_cache, capacity * sizeof(dict_kv_t*));
      if (kv_cache == NULL) {
         return 0;
      }

      d->kv_cache = kv_cache;
      d->capacity = capacity;

      memset(d->kv_cache, 0, capacity * sizeof(dict_kv_t*));

      lst_foreach(it, d->kv_lst) {
         dict_kv_t *kv = lst_iter_data(it);
         _dict_update_index(d, kv);
      }
   }
   return 1;         
}

void*
dict_get(dict_t *d, const char *key, int keylen) {
   if  (d && key && keylen>0) {
      dict_kv_t *kv = _dict_get_kv(d, key, keylen, NULL);
      if (kv) {
         return kv->value;
      }
   }
   return NULL;
}

/* return 1 when success stored
 */
int
dict_set(dict_t *d, const char *key, int keylen, void *value) {
   if (d && key && keylen>0 && value) {
      uint32_t hash = 0;
      dict_kv_t *kv = _dict_get_kv(d, key, keylen, &hash);

      if (kv) {
         kv->value = value;
         return 1;
      }

      if (_dict_expand(d) <= 0) {
         return 0;
      }

      kv = (dict_kv_t*)mm_malloc(sizeof(*kv) + keylen + 1);
      if (kv) {
         kv->node = lst_pushl(d->kv_lst, kv);
         kv->hash = hash;
         kv->value = value;
         kv->keylen = keylen;

         kv->key = (char*)(((unsigned char*)kv) + sizeof(*kv));
         strncpy(kv->key, key, keylen);

         _dict_update_index(d, kv);
         d->count++;
         return 1;
      }
   }
   return 0;
}

void*
dict_remove(dict_t *d, const char *key, int keylen) {
   if (d && key && keylen) {
      dict_kv_t *rkv = _dict_get_kv(d, key, keylen, NULL);
      if (rkv) {
         void *value = rkv->value;
         uint32_t h = rkv->hash % d->capacity;
         dict_kv_t *kv = d->kv_cache[h];

         if (kv == rkv) {
            d->kv_cache[h] = kv->next;
         } else {
            while (kv->next != rkv) {
               kv = kv->next;
            }
            kv->next = rkv->next;
         }

         lst_remove(d->kv_lst, rkv->node);
         mm_free(rkv);

         d->count--;
         return value;
      }
   }
   return NULL;
}

void
dict_foreach(dict_t *d, dict_enumerate_callback cb, void *opaque) {
   if (d && cb) {
      int stop = 0;
      lst_foreach(it, d->kv_lst) {
         dict_kv_t *e = (dict_kv_t*)lst_iter_data(it);
         cb(opaque, e->key, e->keylen, e->value, &stop);
         if (stop) {
            break;
         }
      }
   }
}
