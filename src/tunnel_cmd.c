/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#include "utils_debug.h"
#include "tunnel_cmd.h"
#include <string.h>
#include <assert.h>

#define _err(...) _mlog("cmd", D_ERROR, __VA_ARGS__)
#define _info(...) _mlog("cmd", D_INFO, __VA_ARGS__)
#define _verbose(...) _mlog("cmd", D_VERBOSE, __VA_ARGS__)

int
tunnel_cmd_check(buf_t *b, tunnel_cmd_t *cmd) {
   if (b && cmd && buf_buffered(b)>=TUNNEL_CMD_CONST_HEADER_LEN) {
      memset(cmd, 0, sizeof(*cmd));

      u8 *d = buf_addr(b,buf_ptr(b));
      cmd->data_len = tunnel_cmd_data_len(d, 0, 0);
      cmd->chann_id = tunnel_cmd_chann_id(d, 0, 0);
      cmd->magic = tunnel_cmd_chann_magic(d, 0, 0);
      cmd->cmd = tunnel_cmd_head_cmd(d, 0, 0);
      cmd->payload = &d[TUNNEL_CMD_CONST_HEADER_LEN];

      if (buf_buffered(b) >= cmd->data_len) {
         /* _verbose("chann %d:%d cmd %d, length %d\n", cmd->chann_id, */
         /*          cmd->magic, cmd->cmd, cmd->data_len); */
         return 1;
      }
      /* _err("not enought data %d:%d !\n", buf_buffered(b), cmd->data_len); */
   }
   return 0;
}

u16
tunnel_cmd_data_len(u8 *data, int set, u16 data_len) {
   if (data) {
      if (set) {
         data[0] = (data_len >> 8 ) & 0xff;
         data[1] = data_len & 0xff;
         return data_len;
      }
      else {
         return (data[0] << 8) | data[1];
      }
   }
   return -1;
}

u16
tunnel_cmd_chann_id(u8 *data, int set, u16 chann_id) {
   if (data) {
      int base = 2;
      if (set) {
         data[base+0] = (chann_id >> 8) & 0xff;
         data[base+1] = (chann_id & 0xff);
         return chann_id;
      }
      else {
         return (data[base+0]<<8) | data[base+1];
      }
   }
   return -1;
}

u16
tunnel_cmd_chann_magic(u8 *data, int set, u16 magic) {
   if (data) {
      int base = 2 + 2;
      if (set) {
         data[base+0] = (magic >> 8) & 0xff;
         data[base+1] = (magic & 0xff);
         return magic;
      }
      else {
         return (data[base+0]<<8) | data[base+1];
      }
   }
   return -1;
}

u8
tunnel_cmd_head_cmd(u8 *data, int set, u8 cmd) {
   if (data) {
      int base = TUNNEL_CMD_CONST_HEADER_LEN - 1;
      if (set) {
         data[base] = (cmd & 0xff);
         return cmd;
      }
      else {
         return data[base];
      }
   }
   return TUNNEL_CMD_NONE;
}
