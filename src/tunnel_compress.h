/* 
 * Copyright (c) 2018 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _TUNNEL_COMPRESS_H
#define _TUNNEL_COMPRESS_H

#include "fastlz.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline int tun_compress(int level, const void *input, int length, void *output) {
   return fastlz_compress_level(level, input, length, output);   
}

static inline int tun_decompress(const void *input, int length, void *output, int maxout) {
   return fastlz_decompress(input, length, output, maxout);
}

#ifdef __cplusplus
}
#endif

#endif
