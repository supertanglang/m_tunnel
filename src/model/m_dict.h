/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef M_DICT_H
#define M_DICT_H

#include <stdint.h>

typedef struct s_dict dict_t;


/* helper
 */
typedef uint32_t(*dict_key_hash_callback)(const char *name, int len);

typedef void(*dict_enumerate_callback)(
   void *opaque, const char *key, int keylen, void *value, int *stop);

uint32_t dict_default_key_hash(const char *key, int keylen);




/* interface
 */

// default when capacity_init:0, expand_factor:0, cb:NULL
dict_t* dict_create(int capacity_init, float expand_factor, dict_key_hash_callback cb);
void dict_destroy(dict_t*);

int dict_count(dict_t*);

void* dict_get(dict_t*, const char *key, int keylen);
int dict_set(dict_t*, const char *key, int keylen, void *value);

void* dict_remove(dict_t*, const char *key, int keylen);

void dict_foreach(dict_t*, dict_enumerate_callback cb, void *opaque);

#endif
