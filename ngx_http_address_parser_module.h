#ifndef __NGX_HTTP_ADDRESS_PARSER_MODULE_H__
#define __NGX_HTTP_ADDRESS_PARSER_MODULE_H__

#include <ngx_core.h>

typedef enum {
  ADDRESS_OK,
  ADDRESS_INVALID,
  ADDRESS_UNKNOWN
} address_status;

typedef struct {
  ngx_flag_t enabled;
  ngx_str_t header;
} ngx_http_address_parser_module_loc_conf_t;

#endif
