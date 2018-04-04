/* 
 * Copyright (c) 2018 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

/* m_foundation import example
 */

/* for all */
#define M_FOUNDATION_IMPORT_CRYPTO 1
#define M_FOUNDATION_IMPORT_MODEL  1
#define M_FOUNDATION_IMPORT_PLAT   1
#define M_FOUNDATION_IMPORT_UTILS  1

/* crypto module */
#ifdef M_FOUNDATION_IMPORT_CRYPTO
#define M_FOUNDATION_IMPORT_CRYPTO_MD5     1
#define M_FOUNDATION_IMPORT_CRYPTO_PRNG    1
#define M_FOUNDATION_IMPORT_CRYPTO_RC4     1
#endif  /* M_FOUNDATION_IMPORT_CRYPTO */


/* model module */
#ifdef M_FOUNDATION_IMPORT_MODEL

#define M_FOUNDATION_IMPORT_MODEL_MEM 1
#define M_FOUNDATION_IMPORT_MODEL_DEBUG 1

#define M_FOUNDATION_IMPORT_MODEL_BUF  (M_FOUNDATION_IMPORT_MODEL_MEM)
#define M_FOUNDATION_IMPORT_MODEL_LIST (M_FOUNDATION_IMPORT_MODEL_MEM)

#define M_FOUNDATION_IMPORT_MODEL_MAP  (M_FOUNDATION_IMPORT_MODEL_MEM && \
                                        M_FOUNDATION_IMPORT_MODEL_LIST)
#define M_FOUNDATION_IMPORT_MODEL_SKIPLIST (M_FOUNDATION_IMPORT_MODEL_MEM && \
                                            M_FOUNDATION_IMPORT_CRYPTO_PRNG)

#ifdef TEST_TUNNEL_REMOTE
#define M_FOUNDATION_IMPORT_MODEL_STM (M_FOUNDATION_IMPORT_MODEL_MEM && \
                                       M_FOUNDATION_IMPORT_MODEL_LIST)
#endif

#endif  /* M_FOUNDATION_IMPORT_MODEL */



/* plat module */
#ifdef M_FOUNDATION_IMPORT_PLAT

/* some type relative func under win */
#define M_FOUNDATION_IMPORT_PLAT_TYPE 1

/* for win to cover string to UTF-8 */
//#define M_FOUNDATION_IMPORT_PLAT_CHARSET 1

/* time for win/nix */
#define M_FOUNDATION_IMPORT_PLAT_TIME    1

//#define M_FOUNDATION_IMPORT_PLAT_DIR (M_FOUNDATION_IMPORT_MODEL_MEM && \
//                                      M_FOUNDATION_IMPORT_MODEL_DEBUG && \
//                                      M_FOUNDATION_IMPORT_PLAT_CHARSET)
/* thread operation for win/nix*/
#define M_FOUNDATION_IMPORT_PLAT_THREAD (M_FOUNDATION_IMPORT_MODEL_MEM && \
                                         M_FOUNDATION_IMPORT_MODEL_LIST && \
                                         M_FOUNDATION_IMPORT_PLAT_TIME)
#endif  /* M_FOUNDATION_IMPORT_PLAT */


/* utils module */
#ifdef M_FOUNDATION_IMPORT_UTILS

/* utils for get value from args  */
#define M_FOUNDATION_IMPORT_UTILS_ARGS (M_FOUNDATION_IMPORT_MODEL_MEM && \
                                        M_FOUNDATION_IMPORT_MODEL_LIST)
/* string split, pattern matching */
#define M_FOUNDATION_IMPORT_UTILS_STR (M_FOUNDATION_IMPORT_MODEL_MEM && \
                                       M_FOUNDATION_IMPORT_MODEL_DEBUG && \
                                       M_FOUNDATION_IMPORT_PLAT_TYPE)
#endif  /* M_FOUNDATION_IMPORT_UTILS */
