/* 
 * Copyright (c) 2015 lalawue
 * 
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the MIT license. See LICENSE for details.
 */

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>

#include "m_mem.h"
#include "utils_conf.h"

#define _err(...) do { printf("[conf] "); printf(__VA_ARGS__); } while (0)

typedef struct {
   str_t *key;
   str_t *value;
} conf_entry_t;

struct s_conf {
   lst_t *entry_lst;
   void  *opaque_content;
   void  *opaque_str;
};

conf_t*
utils_conf_open(const char *conf_file) {
   //mm_report(2);
   conf_t *cf = NULL;
   FILE *fp = fopen(conf_file, "rb");
   if (fp) {
      if (fseek(fp, 0, SEEK_END) == 0) {

         long flength = ftell(fp);
         char *fcontent = (char*)mm_malloc(flength);
         
         rewind(fp);
         if (fread(fcontent, flength, 1, fp) > 0) {

            lst_t *lst = lst_create();
            str_t *head = str_clone_cstr(fcontent, flength);
            str_t *h = str_split(head, "\n", 0);

            if (h) {
               str_foreach(ith, h) {
                  str_t *it = str_trim(ith, '\r');
                  if (str_len(it)>0 || str_locate(it, "#", 0)>0) {
                     int i = str_locate(it, "=", 0);
                     if (i > 0) {
                        conf_entry_t *ce = (conf_entry_t*)mm_malloc(sizeof(*ce));
                        ce->key = str_sub(it, 0, i);
                        ce->value = str_sub(it, i+1, str_len(it));
                        lst_pushl(lst, ce);
                     }
                  }
               }

               cf = (conf_t*)mm_malloc(sizeof(*cf));
               cf->entry_lst = lst;
               cf->opaque_content = fcontent;
               cf->opaque_str = head;
            }
            else {
               _err("empty conf file !\n");
               lst_destroy(lst);
            }
         }
         else {
            _err("fail to read [%s] !\n", conf_file);
            mm_free(fcontent);
         }
      }
      else {
         _err("fail to seek conf file !\n");
      }
      fclose(fp);
   }
   else {
      _err("fail to open conf file !\n");
   }
   return cf;
}

void
utils_conf_close(conf_t *cf) {
   if (cf) {
      mm_free(cf->opaque_content);
      str_destroy((str_t*)cf->opaque_str);
      while (lst_count(cf->entry_lst) > 0) {
         mm_free(lst_popf(cf->entry_lst));
      }
      lst_destroy(cf->entry_lst);
      mm_free(cf);
      //mm_report(2);
   }
}

str_t*
utils_conf_value(conf_t *cf, const char *key) {
   str_t *val = NULL;
   if (cf && key) {
      lst_foreach(it, cf->entry_lst) {
         conf_entry_t *ce = (conf_entry_t*)lst_iter_data(it);

         if (str_cmp(ce->key, key, 0) == 0) {
            val = ce->value;
            break;
         }
      }
   }
   return val;
}
