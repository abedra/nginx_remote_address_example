# HTTP at the Edge: Determining Remote Address

## Introduction

Almost anything worth deploying in production will be deployed in layers with multiple proxies. This can make understanding the IP address of the actual requester difficult.


https://jychp.medium.com/how-to-bypass-cloudflare-bot-protection-1f2c6c0c36fb

## Project Setup

Since this is going to be an [NGINX](https://nginx.org/) module, there's a few things that are relevant to get setup before we get started. First, we will need a copy of the NGINX source code so we can compile our module. I've been using this [bootstrap script](https://github.com/abedra/nginx_remote_address_example/blob/master/script/bootstrap) for several years now and it's been a tremendous help. It creates a complete NGINX environment that's entirely contained within the project directory. This allows you to isolate your development to a single location. Since it pulls down and compiles NGINX inside the project directory, it also provides an easy way for your editor to include all of the NGINX headers without having to explicitly identify them.

There are quite a few dependencies necessary to compile NGINX, and those should be installed prior to running the bootstrap script. You can read more about those [here](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-open-source/). Once you have those setup you can run `make bootstrap` to get things started.

The example project has the following layout:

* ngx_http_address_parser_module.[c|h] - Source code
* config - Instructions for NGINX on how to build the module
* nginx.conf - NGINX conf file (symlinked into the built NGINX folder on bootstrap)
* t - Test code
* Makefile - Ergonomics 

NGINX modules can be compiled statically and included into the final `nginx` binary, or can be compiled as a shared object and loaded dynamically inside `nginx.conf`. The `config` file for our module allows either. Supporting both is trivial and should be considered best practice.

## Test Suite

A testing library has been developed to help test how NGINX will act with specific configuration options. This library can be used to test a vanilla NGINX install with your configuration to verify that you have configured it properly, or it can be used to test custom modules. You will need to have some version of [CPAN](https://www.cpan.org/) installed. I recommend [cpanm](https://github.com/miyagawa/cpanminus) to avoid the overhead of traditional cpan and make CI a little easier to setup. You will need to install the following dependencies to run the tests:

```sh
cpanm -S install Test::Nginx Test::Nginx::Socket
```

With this foundation, we can actually test drive our module from start to finish. This may seem like a trivial concept, but considering we are writing C code that plugs into a very large ecosystem, this is an absolute game changer. Let's create our first test:

```perl
use Test::Nginx::Socket 'no_plan';

no_shuffle();
run_tests();

__DATA__
=== TEST 1: Module not configured (200)
--- config
location = /t {
  echo 'test';
}
--- request
GET /t
--- error_code: 200

=== TEST 2: Module explicitly disabled (200)
--- config
location = /t {
  address_parser off;
  echo 'test';
}
--- request
GET /t
--- error_code: 200

```

This test represents what happens when nothing is in the equation. We have no module configured and nothing but a text response of `test` returned. This may not seem like an important test right now, but as we develop our module it will become an important test to verify our module does not interfere with NGINX when it is not enabled. It's considered proper etiquite for a module to not perform any actions if it not setup or enabled. The second test shows that our module does nothing when it is explicitly disabled.

## Connected Socket Address

Now that we have a foundation we can start to build our module. Let's start with a test that will help us identify our next target:

```perl
use Test::Nginx::Socket 'no_plan';

no_shuffle();
run_tests();

__DATA__
=== TEST 1: Module enabled, no header configured
--- config
location = /t {
  address_parser on;
  echo 'test';
}
--- request
GET /t
--- error_code: 200
--- response_headers
X-Derived-Address: 127.0.0.1

```

This test configures the module to be active. It now expects the header `X-Derived-Address` to be present with a value of `127.0.0.1`. This is the first thing we will need to build into our module. To do so we will need the following:

* The ability to get the IP address of the connection as NGINX sees it
* The ability to create and set the value of a custom header

With a failing test in hand, let's explore the NGINX api to see how we can get what we need. It should be no surprise that the connection holds some notion of who is connected. The request is of type `ngx_http_request_t *` and is accessible on every request presented to the module. If you want to obtain the information about the socket associated with the request you can ask the request for the `connection->addr_text` member. It will provide you with an `ngx_str_t` that contains the information we are looking for. This value should be considered already processed and safe to use. No additional validation or verification is required. A small modification to our module handler can get this done:

```c
static ngx_int_t ngx_http_address_parser_module_handler(ngx_http_request_t *r) {
  if (r->main->internal) {
    return NGX_DECLINED;
  }

  ngx_http_address_parser_module_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_address_parser_module);

  if (!loc_conf->enabled || loc_conf->enabled == NGX_CONF_UNSET) {
    return NGX_DECLINED;
  }

  set_derived_address_header(r, &r->connection->addr_text);

  return NGX_OK;
}
```

Setting a custom header requires some additional code. The `set_derived_address_header` is defined as follows:

```c
static void set_derived_address_header(ngx_http_request_t *r, ngx_str_t *address) {
  ngx_table_elt_t *h;
  h = ngx_list_push(&r->headers_out.headers);
  h->hash = 1;
  ngx_str_set(&h->key, "X-Derived-Address");
  h->value = *address;
}
```

Let's quickly acknowledge that setting an outbound header with this data is about the least valuable thing one could do with the data, and would work against us if an attacker was on the other end. In order to avoid introducing too many concepts at once, we will continue to use this mechanism while building the module so we can easily test drive what we want to accomplish. The end of this post will introduce creating and setting custom variables within NGINX that will allow us to do whatever we desire with the data. This will offer flexibility under test, but give us the ability to use it however we desire in practice.

## Handling X-Forwarded-For

The next stop on our journey is using the `X-Forwarded-For` header if is present and populated. Defined in [RFC 7239](https://tools.ietf.org/html/rfc7239), the `X-Forwarded-For` header allows proxies to keep track of the chain of IP addresses that have participated in routing the request. Being part of the overall specification for HTTP, we can expect NGINX to have an understanding built in. While this is true, the information provided is more complex than that provided by the connected socket address. What's inside this header can vary, and we must expect that it will be a comma separated list of addresses. That being said, we can also rely on the IP address that we are directly in search of is the first in this list, so extracting it won't require processing the entire string. NGINX provides this header as part of the `headers_in` member of the request.

Lets start with a test:

```fundamental
=== TEST 2: Module enabled, XFF provided, one IP
--- config
location = /t {
  address_parser on;
  echo 'test';
}
--- request
GET /t
--- more_headers
X-Forwarded-For: 1.1.1.1
--- error_code: 200
--- response_headers
X-Derived-Address: 1.1.1.1

```

Since we don't currently account for `X-Forwarded-For`, this test will fail because the derived address will be `127.0.0.1`. With a small bit of code we can get it to a better place:

```c
ngx_array_t *xff_header_array = &r->headers_in.x_forwarded_for;
if (xff_header_array != NULL && xff_header_array->nelts == 1) {
  ngx_table_elt_t **xff_elements = xff_header_array->elts;
  ngx_str_t xff = xff_elements[0]->value;
  set_derived_address_header(r, &xff);
} else {
  set_derived_address_header(r, &r->connection->addr_text);
}
```

This change checks for the presence of the `X-Forwarded-For` header and uses that if present. It falls through to the connected socket address if not set. This will satisfy our current tests, but will fail if the `X-Forwarded-For` header contains multiple addresses. Let's demonstrate:

```c
=== TEST 3: Module enabled, XFF provided, multiple address
--- config
location = /t {
  address_parser on;
  echo 'test';
}
--- request
GET /t
--- more_headers
X-Forwarded-For: 1.1.1.1, 2.2.2.2, 3.3.3.3
--- error_code: 200
--- response_headers
X-Derived-Address: 1.1.1.1

```

Until we parse this into a single value, we won't be able to satisfy the next requirement. There are a few options here, but since we have a pretty straight forward task of consuming the start of the string to first comma, we can just walk the string to get there. Using a regex or splitting the string would be overkill for this task and slower than a character walk.

```c
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
set_derived_address_header(r, &address);
```

Before we attempt to operate on the value of the `X-Forwarded-For` header, we should verify it actually has something to work with. If not, we should stop the request and return. For this example I chose to return a `400` to keep things easy, but it's ultimately up to you how you want to handle the presence of the header with no actual value. Next we walk the string looking for a `space` or a `comma`. Once we encounter that, we break. Our walk changes the position of the pointer in the string, and subtracting that from the full string gives us the length of the output address string. We can then allocate our address string and copy in the part of the header that's relevant to us. It's important to note the use of `ngx_pnalloc` here. If we use the NGINX allocators and the pool available for the request, we will guaranteed that any allocations made will be accounted for when the request completes. This dramatically simplifies memory management. While we're here, let's add a test that shows the behavior when no value is supplied for the `X-Forwarded-For` header:

```fundamental
=== TEST 4: Module enabled, XFF provided, no value
--- config
location = /t {
  address_parser on;
  echo 'test';
}
--- request
GET /t
--- more_headers
X-Forwarded-For:
--- error_code: 400

```

Our next test is now passing. It's time to address the last item on the `X-Forwarded-For` processing checklist. We need to verify that the address extracted from the header is a valid IP address. Since this header can be supplied by the user, we need to be diligent and assume that it can come in broken or potentially malicious.

```fundamental
=== TEST 5: Module enabled, XFF provided, invalid address
--- config
location = /t {
  address_parser on;
  echo 'test';
}
--- request
GET /t
--- more_headers
X-Forwarded-For: not an IP address
--- error_code: 400

```

Currently, this will fail with a response code of `200`, and set the value of the `X-Derived-Address` to `not`. That's less than desirable, so let's put something in place to halt the request and return a `400` if the extracted value is not a valid IP address.

```c
char terminated_comparator[INET6_ADDRSTRLEN] = {'\0'};
memcpy(terminated_comparator, address.data, address.len);
unsigned char ipv4[sizeof(struct in_addr)];
unsigned char ipv6[sizeof(struct in6_addr)];

if (inet_pton(AF_INET,  (const char *)&terminated_comparator, ipv4) == 1 || 
    inet_pton(AF_INET6, (const char *)&terminated_comparator, ipv6) == 1) {
  set_derived_address_header(r, &address);
} else {
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "%V is not a valid IP address", &address);
  return NGX_HTTP_BAD_REQUEST;
}
```

One of the downsides to using the NGINX api is that the string type used, `ngx_str_t` is a struct whos `data` member is a non null terminated `u_char *`. If you want to use an `ngx_str_t` with traditional C library functions, you need to either null terminate your `ngx_str_t` values up front and deal with the extra character, or find a way to provide null terminated versions of the value. In this case I chose to keep the address non null terminated to avoid any consumer issues outside of the address validation and create a temporary terminated string for the `inet_pton` call. Since we have no way of knowing if the `X-Forwarded-For` header will pass in IPv4 or IPv6 addresses, we need to consider both. The good news is that a call to `inet_pton` can give you the validation necessary to understand if you have a proper IP address. With this code in hand our newest test now passes.

## Using a Custom Header

## Security Considerations

## Real World Usage

## Wrap-Up
