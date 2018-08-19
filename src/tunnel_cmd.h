/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#ifndef TUNNEL_CMD_H
#define TUNNEL_CMD_H

#include "m_buf.h"

typedef unsigned char  u8;
typedef unsigned short u16;

/* [                       HEADER                    ] 
 * TOTAL_DATA_LEN | CHANN_ID |  MAGIC   | TUNNEL_CMD | PAYLOAD
 * 2 bytes        | 2 bytes  |  2 bytes | 1 byte     | n bytes
 *
 * support data < 2^16 (65536 , 64k)
 */

#define TUNNEL_CMD_CONST_HEADER_LEN 7

#define TUNNEL_CMD_CONST_DATA_LEN_OFFSET 2

#define TUNNEL_CHANN_BUF_SIZE  32768 /* 32Kb */
#define TUNNEL_CHANN_DATA_SIZE 30720 /* for fastlz */

#define TUNNEL_CHANN_FASTLZ_MIN_LEN 132 /* min 66 length for fastlz output */

#define TUNNEL_CHANN_MAX_COUNT (3072) /* enough for normal web browse */

typedef struct {
   u16 data_len;                /* data length */
   u16 chann_id;                /* tcp channel index */
   u16 magic;                   /* for channel reuse identity */
   u8  cmd;                     /* cmd */
   u8  *payload;                /* payload */
} tunnel_cmd_t;

/* cmd and payload layout */
enum {
   TUNNEL_CMD_NONE = 0,

   TUNNEL_CMD_ECHO,
   /* REQUEST : ECHO_VAL
                1 byte
      RESPONSE: 1
    */

   TUNNEL_CMD_AUTH,
   /* REQUEST : AUTH_TYPE | USER_NAME | PASSWORD_PAYLOAD
                1 byte    | 32 byte   | 32 bytes

      RESPONSE: AUTH_TYPE | CRYPTO_SALT
                1 byte    | 32 byte

      NOTE    : AUTH_TYPE 0:fail 1:req salt 2:USER_NAME PASS_WORD
    */

   TUNNEL_CMD_CONNECT,
   /* REQUEST : ADDR_TYPE | PORT_PAYLOAD | ADDR_PAYLOAD | NULL
                1 byte    | 2 bytes      |  n bytes     | '\0'

      RESPONSE: RESULT | PORT_PAYLOAD | ADDR_PAYLOAD
                1 byte | 2 bytes      | 4 bytes

      NOTE    : ADDR_TYPE should be 0/1 (dot numberic/domain)
                RESULT should be 0/1 (failure/success), failure will ignore ADDR and PORT
    */

   TUNNEL_CMD_CLOSE,
   /* REQUEST : CLOSE_VAL
                (1) 1 bytes

      RESPONSE: CLOSE_VAL
                (0) 1 bytes
      NOTE    : the RESPONSE only comes from remote, for local sync chann_id state
    */

   TUNNEL_CMD_DATA_RAW,
   /* REQUEST : DATA_PAYLOAD
                n bytes

      NO RESPONSE

      NOTE    : raw data no compression
    */

   TUNNEL_CMD_DATA_COMPRESSED,
   /* REQUEST : DATA_PAYLOAD
                n bytes

      NO RESPONSE

      NOTE    : data with compression
    */
};

enum {
   TUNNEL_ADDR_TYPE_IP = 0,
   TUNNEL_ADDR_TYPE_DOMAIN,
   TUNNEL_ADDR_TYPE_INVALID,    /* for connection failure */
};

int tunnel_cmd_check(buf_t *b, tunnel_cmd_t *cmd);

/* data should be buffer header */
u16 tunnel_cmd_data_len(u8 *data, int set, u16 data_len);
u16 tunnel_cmd_chann_id(u8 *data, int set, u16 chann_id);
u16 tunnel_cmd_chann_magic(u8 *data, int set, u16 magic);
u8  tunnel_cmd_head_cmd(u8 *data, int set, u8 cmd);

#endif
