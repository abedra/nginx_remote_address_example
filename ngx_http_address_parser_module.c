#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>

#include "ngx_http_address_parser_module.h"

ngx_module_t ngx_http_address_parser_module;

static void set_derived_address_header(ngx_http_request_t *r, ngx_str_t *address) {
  ngx_table_elt_t *h;
  h = ngx_list_push(&r->headers_out.headers);
  h->hash = 1;
  ngx_str_set(&h->key, "X-Derived-Address");
  h->value = *address;
}

static ngx_int_t ngx_http_address_parser_module_handler(ngx_http_request_t *r) {
  if (r->main->internal) {
    return NGX_DECLINED;
  }

  ngx_http_address_parser_module_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_address_parser_module);

  if (!loc_conf->enabled || loc_conf->enabled == NGX_CONF_UNSET) {
    return NGX_DECLINED;
  }

  ngx_array_t *xff_header_array = &r->headers_in.x_forwarded_for;
  if (xff_header_array != NULL && xff_header_array->nelts == 1) {
    ngx_table_elt_t **xff_elements = xff_header_array->elts;
    ngx_str_t xff = xff_elements[0]->value;

    if (xff.len == 0) {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "X-Forwarded-For present but no value provided");
      return NGX_HTTP_BAD_REQUEST;
    }

    ngx_str_t address = ngx_null_string;
    u_char *p;
    for (p = xff.data; p < (xff.data + xff.len); p++) {
      if (*p == ' ' || *p == ',') {
        break;
      }
    }
    
    address.len = p - xff.data;
    address.data = ngx_pnalloc(r->pool, address.len);
    ngx_memcpy(address.data, xff.data, address.len);

    char terminated_comparator[INET6_ADDRSTRLEN] = {'\0'};
    memcpy(terminated_comparator, address.data, address.len);
    unsigned char ipv4[sizeof(struct in_addr)];
    unsigned char ipv6[sizeof(struct in6_addr)];

    if (inet_pton(AF_INET, (const char *)&terminated_comparator, ipv4) == 1 || inet_pton(AF_INET6, (const char *)&terminated_comparator, ipv6) == 1) {
      set_derived_address_header(r, &address);
    } else {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%V is not a valid IP address", &address);
      return NGX_HTTP_BAD_REQUEST;
    }
  } else {
    set_derived_address_header(r, &r->connection->addr_text);
  }

  return NGX_OK;
}

static ngx_int_t ngx_http_address_parser_module_init(ngx_conf_t *cf) {
  ngx_http_handler_pt *h;
  ngx_http_core_main_conf_t *cmcf;

  cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
  h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

  if (h == NULL) {
    return NGX_ERROR;
  }

  *h = ngx_http_address_parser_module_handler;

  return NGX_OK;
}

static ngx_command_t ngx_http_address_parser_module_commands[] = {
  {
    ngx_string("address_parser"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_address_parser_module_loc_conf_t, enabled),
    NULL
  },
  ngx_null_command
};

static void* ngx_http_address_parser_module_create_loc_conf(ngx_conf_t *cf) {
  ngx_http_address_parser_module_loc_conf_t *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_address_parser_module_loc_conf_t));
  if (conf == NULL) {
    return NULL;
  }

  conf->enabled = NGX_CONF_UNSET;
  
  return conf;
}

static char* ngx_http_address_parser_module_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  ngx_http_address_parser_module_loc_conf_t *prev = (ngx_http_address_parser_module_loc_conf_t *) parent;
  ngx_http_address_parser_module_loc_conf_t *conf = (ngx_http_address_parser_module_loc_conf_t *) child;

  ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

  return NGX_CONF_OK;
}

static ngx_http_module_t ngx_http_address_parser_module_ctx = {
  NULL,                                           /* preconfiguration */
  ngx_http_address_parser_module_init,            /* postconfiguration */
  NULL,                                           /* create main configuration */
  NULL,                                           /* init main configuration */
  NULL,                                           /* create server configuration */
  NULL,                                           /* merge server configuration */
  ngx_http_address_parser_module_create_loc_conf, /* create location configuration */
  ngx_http_address_parser_module_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_address_parser_module = {
  NGX_MODULE_V1,
  &ngx_http_address_parser_module_ctx,     /* module context */
  ngx_http_address_parser_module_commands, /* module directives */
  NGX_HTTP_MODULE,                         /* module type */
  NULL,                                    /* init master */
  NULL,                                    /* init module */
  NULL,                                    /* init process */
  NULL,                                    /* init thread */
  NULL,                                    /* exit thread */
  NULL,                                    /* exit process */
  NULL,                                    /* exit master */
  NGX_MODULE_V1_PADDING
};
