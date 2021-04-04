#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>

#include "ngx_http_address_parser_module.h"

ngx_module_t ngx_http_address_parser_module;

static address_status remote_address(ngx_http_request_t *r, ngx_str_t *address) {
  address->len = r->connection->addr_text.len;
  address->data = ngx_pnalloc(r->pool, address->len);
  ngx_memcpy(address->data, r->connection->addr_text.data, r->connection->addr_text.len); 

  return ADDRESS_OK;
}

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

  ngx_str_t address = ngx_null_string;
  address_status address_parser_result = remote_address(r, &address);
  if (address_parser_result != ADDRESS_OK) {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid Address");
  } else {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Address: %V", &address);
    set_derived_address_header(r, &address);
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
