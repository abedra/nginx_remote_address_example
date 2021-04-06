# HTTP at the Edge: Determining Remote Address

## Introduction

When it comes to web applications, almost anything worth deploying in production will be deployed in layers with multiple proxies. This can make understanding the IP address of the actual requester difficult. A basic understanding of who is connecting to you is a valuable asset in managing traffic and making the most efficient use of your assets. I came across [a post](https://jychp.medium.com/how-to-bypass-cloudflare-bot-protection-1f2c6c0c36fb) recently that claimed to bypass CloudFlare's ability to identify an actor. The response provided by CloudFlare was spot on, but there wasn't a follow on explanation by the author of why the `X-Forwarded-For` header should not be trusted as a mechanism for providing this information to a web application.

Rather than just point to [RFC 7239](https://tools.ietf.org/html/rfc7239) and talk through the right way to derive an address, I thought it would be fun to write this from scratch in a generic way. This post will implement a custom NGINX module in C that provides several ways of discovering the IP of the actor and explain the various scenarios that one should consider when determining if you can trust the information.

You can find the complete implementation [here](https://github.com/abedra/nginx_remote_address_example).

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

One of the downsides to using the NGINX api is that the string type used, `ngx_str_t` is a struct whos `data` member is a non null terminated `u_char *`. If you want to use an `ngx_str_t` with traditional C library functions, you need to either null terminate your `ngx_str_t` values up front and deal with the extra character, or find a way to provide null terminated versions of the value. In this case I chose to keep the address non null terminated to avoid any consumer issues outside of the address validation and create a temporary terminated string for the `inet_pton` call. Since we have no way of knowing if the `X-Forwarded-For` header will pass in IPv4 or IPv6 addresses, we need to consider both. The good news is that a call to `inet_pton` can give you the validation necessary to understand if you have a proper IP address. With this code in hand our newest test now passes. Since we haven't yet considered IPv6 addresses, let's add tests for both full and abbreviated forms:

```fundamental
=== TEST 6: Module enabled, XFF provided, IPv6 address
--- config
location = /t {
  address_parser on;
  echo 'test';
}
--- request
GET /t
--- more_headers
X-Forwarded-For: 2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b
--- error_code: 200
--- response_headers
X-Derived-Address: 2001:0db8:3c4d:0015:0000:0000:1a2f:1a2b

=== TEST 7: Module enabled, XFF provided, IPv6 abbreviated address
--- config
location = /t {
  address_parser on;
  echo 'test';
}
--- request
GET /t
--- more_headers
X-Forwarded-For: 2001:db8:3c4d:15::1a2f:1a2b
--- error_code: 200
--- response_headers
X-Derived-Address: 2001:db8:3c4d:15::1a2f:1a2b

```

## Using a Custom Header

The last item on our list of options is using a custom header to derive the address. Most CDN providers have the option to enable a header that they are responsible for maintaining. Since they use a custom header, they are free from any rules around the handling of that header and can choose options like overwritting the header regardless of input conditions, which is one of the major reasons trusting the `X-Forwarded-For` header is a dangerous choice if you truly need to determine the connecting IP address.

In order to facilitate usage of a custom header, we will need to tell our module what header to look for in the incomming requests. This means we will need to add one more directive and corresponding configuration value. Let's start by adding a member to the module's configuration struct:

```c
typedef struct {
  ngx_flag_t enabled;
  ngx_str_t header;
} ngx_http_address_parser_module_loc_conf_t;
```

This provides us a place to put the configuration value. In order to capture it, we need to add a directive to the module. The resulting directives list is as follows:

```c
static ngx_command_t ngx_http_address_parser_module_commands[] = {
  {
    ngx_string("address_parser"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_address_parser_module_loc_conf_t, enabled),
    NULL
  },
  {
    ngx_string("address_parser_custom_header"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_address_parser_module_loc_conf_t, header),
    NULL
  },
  ngx_null_command
};
```

We will also need to handle merging any configuration changes. Because we allow these directives to be set at any level, it's important to properly merge them in. Our merge function will get one additional line to accomodate:

```c
static char* ngx_http_address_parser_module_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
  ngx_http_address_parser_module_loc_conf_t *prev = (ngx_http_address_parser_module_loc_conf_t *) parent;
  ngx_http_address_parser_module_loc_conf_t *conf = (ngx_http_address_parser_module_loc_conf_t *) child;

  ngx_conf_merge_value(conf->enabled,    prev->enabled, 0);
  ngx_conf_merge_str_value(conf->header, prev->header,  "");

  return NGX_CONF_OK;
}
```

With this we have enough to write the next failing test:

```fundamental
=== TEST 8: Module enabled, custom header configured, custom header provided
--- config
location = /t {
  address_parser on;
  address_parser_custom_header "X-Parser-Test-IP";
  echo 'test';
}
--- request
GET /t
--- more_headers
X-Parser-Test-IP: 1.1.1.1
--- error_code: 200
--- response_headers
X-Derived-Address: 1.1.1.1

```

Since we don't look for the configured custom header, we can't expect this to pass yet. Doing so requires a little more code than any of our previous endeavors. While all headers are accounted for in the request struct, only the headers defined by the HTTP spec are available by name. All other headers need to be resolved by looking them up in the request hash. To do this we will need to iterate over the incoming headers and check for a match. We can insert the following code above the rest of our processing logic in the handler, as it will take priority over the other options:

```c
ngx_list_part_t *headers_list = &r->headers_in.headers.part;
ngx_table_elt_t *headers = headers_list->elts;
ngx_table_elt_t *custom_address_header = NULL;
for (ngx_uint_t i = 0; ; i++) {
  if (i >= headers_list->nelts) {
    if (headers_list->next == NULL) {
      break;
    }

    headers_list = headers_list->next;
    headers = headers_list->elts;
    i = 0;
  }

  if (ngx_strncmp(headers[i].key.data, loc_conf->header.data, headers[i].key.len) == 0) {
    custom_address_header = &headers[i];
  }
}

if (custom_address_header != NULL) {
  set_derived_address_header(r, &custom_address_header->value);
  return NGX_OK;
}
```

This brute force search is expensive, but not horribly so. We could optimize it by hashing the header name provided and comparing the hashed values instead of the header name strings, but for the sake of this conversation this is sufficient to get us to our desired end state. If the header is found in the request, set the `X-Derived-Address` header to its value. This assumes that the value in the custom header will only ever be a single value. If your custom header is a collection of addresses, you will need to adjust accordingly. Our newest test will now pass, but there are several more tests to write that will prove the existence of a few bugs. First, let's test the condition that the directive is configured but no header is provided:

```fundamental
=== TEST 9: Module enabled, custom header configured, custom header not provided
--- config
location = /t {
  address_parser on;
  address_parser_custom_header "X-Parser-Test-IP";
  echo 'test';
}
--- request
GET /t
--- error_code: 400

```

This test will fail because we continue to fall through if the header is not found. This will result in a `200` response code and the derived address equal to the value of the connected socket address. We can quickly fix this by adding a branch to our presence check on the value of `custom_address_header`, but we will quickly realize that all of this code should only be run under the condition that the `address_parser_custom_header` directive is actually configured. We can fix that by adding `if (loc_conf->header.len > 0) {` around the code above. With the custom header conditionally handled we can safely fail to `400` if it's configured and not found.

```c
if (custom_address_header != NULL) {
  set_derived_address_header(r, &custom_address_header->value);
  return NGX_OK;
} else {
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Header %V not present in request", &loc_conf->header);
  return NGX_HTTP_BAD_REQUEST;
}
```

This will let the absence test pass, but if you've been following along closely enough you will realize that we aren't yet validating the address provided. Let's write a test that demonstrates the issue:

```fundamental
=== TEST 10: Module enabled, custom header configured, custom header address not valid
--- config
location = /t {
  address_parser on;
  address_parser_custom_header "X-Parser-Test-IP";
  echo 'test';
}
--- request
GET /t
--- more_headers
X-Parser-Test-IP: not an IP address
--- error_code: 400

```

So far there's been a general resistence to refactoring and almost all of the handler code is in the same function. Because the validation will be the same for all cases, let's extract it:

```c
static address_status validate_address(ngx_str_t *address) {
  char terminated_comparator[INET6_ADDRSTRLEN] = {'\0'};
  memcpy(terminated_comparator, address->data, address->len);
  unsigned char ipv4[sizeof(struct in_addr)];
  unsigned char ipv6[sizeof(struct in6_addr)];

  if (inet_pton(AF_INET, (const char *)&terminated_comparator, ipv4) == 1 || 
      inet_pton(AF_INET6, (const char *)&terminated_comparator, ipv6) == 1) {
    return ADDRESS_OK;
  } else {
    return ADDRESS_INVALID;
  }
}
```

We can now use this in both places where valiation is necessary. Next, we should be sure to test behavior when both `X-Forwarded-For` and our configured header are supplied:

```fundamental
=== TEST 11: Module enabled, custom header configured, XFF and custom header provided
--- config
location = /t {
  address_parser on;
  address_parser_custom_header "X-Parser-Test-IP";
  echo 'test';
}
--- request
GET /t
--- more_headers
X-Forwarded-For: 1.1.1.1
X-Parser-Test-IP: 2.2.2.2
--- error_code: 200
--- response_headers
X-Derived-Address: 2.2.2.2

```

This captures our preference over the `X-Forwarded-For` header.

## Cleanup

At this point there's a lot going on in the main handler. I tend to try to keep that as slim as possible. A little time with the handler can produce the following:

```c
static ngx_int_t ngx_http_address_parser_module_handler(ngx_http_request_t *r) {
  if (r->main->internal) {
    return NGX_DECLINED;
  }

  ngx_http_address_parser_module_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_address_parser_module);

  if (!loc_conf->enabled || loc_conf->enabled == NGX_CONF_UNSET) {
    return NGX_DECLINED;
  }

  ngx_str_t address = ngx_null_string;
  address_status status = derive_address(r, loc_conf, &address);
  switch (status) {
    case ADDRESS_OK:
      set_derived_address_header(r, &address);
      return NGX_OK;
    case ADDRESS_UNKNOWN:
      set_derived_address_header(r, &r->connection->addr_text);
      return NGX_OK;
    case ADDRESS_INVALID:
      return NGX_HTTP_BAD_REQUEST;
    default:
      return NGX_OK;
  }
}
```

The rest of the refactoring is cut from this post for the sake of brevity, but it can be viewed in full [here](https://github.com/abedra/nginx_remote_address_example/blob/master/ngx_http_address_parser_module.c). At this point our full set of tests still pass. Before we consider additional tests and features, we need to talk security.

## Security Considerations

Determining the real IP address of a connecting party can be unreliable at best when multiple proxies are involved. There are only a few ways to get this information in what can be considered a best effort or "probably accurate" fashion. In order to rely on this data it's important to know what can and cannot be modified by the requester, and set your expectations accordingly. It's good to lean on CDN providers to source this information as they have some of the best infrastructure in which to provide the data. IP spoofing is mostly a thing of the past, but hopping mechanisms like tor are still alive and well, and should be accounted for. There are some ways to identify tor exit nodes and restrict traffic from those addresses, but it's a constantly evolving game that you should only pursue if you have the real means to do so. This comes in both money and time, and takes a village to get right.

At the end of the day it's good to create controls that act on IP addresses. You will undoubtedly cause a little unintended consequences, but you shouldn't let that discourage you from pursing this as a means to control traffic.

## Real World Usage

As previously stated, adding the derived address back to the outbound response headers is fairly useless and likely does more harm than good. It was done initially to support the tests used to drive this process. The good news is that we can have our cake and eat it to. NGINX offers an API to create variables that can be used outside of the module. With a little more code we can set the variable to the derived address and allow the consumer of the module to use that variable at their discretion. This means we can use the variable to set an outbound header inside our tests and maintain our setup and expectations with slight tweaks to the individual test configurations without any loss in fidelity. Let's start by adding a function to inject variables into the module:

```c
// Somewhere near the top of the file
ngx_str_t derived_address_variable_name = ngx_string("derived_address");

// ...
static ngx_int_t ngx_http_address_parser_module_add_variables(ngx_conf_t *cf) {
  ngx_http_variable_t *var = ngx_http_add_variable(cf, &derived_address_variable_name, NGX_HTTP_VAR_NOCACHEABLE);
  
  if (var == NULL) {
    return NGX_ERROR;
  }
  
  var->get_handler = get_derived_address;
  var->data = 0;

  return NGX_OK;
}
```

This function will add a single variable named `derived_address`, available to any configuration where the module is loaded. a function named `get_derived_address` is assigned to the `get_handler` member of our variable. Let's define that now:

```c
static ngx_int_t get_derived_address(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
  ngx_http_address_parser_module_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_address_parser_module);

  if (!loc_conf->enabled || loc_conf->enabled == NGX_CONF_UNSET) {
    return NGX_OK;
  }

  ngx_str_t address = ngx_null_string;
  address_status status = derive_address(r, loc_conf, &address);
  switch (status) {
    case ADDRESS_OK:
      v->len = address.len;
      v->valid = 1;
      v->no_cacheable = 0;
      v->not_found = 0;
      v->data = address.data;
      return NGX_OK;
    case ADDRESS_UNKNOWN:
    case ADDRESS_INVALID:
    default:
      return NGX_OK;
  }
}
```

This should look strikingly similar to the module handler. That's because this code will now supplant our handler and be the only real code run on a request. Our goal as a module will shift from controlling the request directly to making a variable available that can be evaluated and operated on within the NGINX configuration itself, leaving ultimate control to the consumer of the module. I find that relinquishing control from the module back to the configuration as cleanly and quickly as possible is a good practice. You should also notice that there's only one case that results in the variable being populated. The rest fall through to returning `NGX_OK` without setting any data. The behavior change that this will produce is in the case of nothing found nothing will happen and it will be up to the configuration to decide if adding a header with the connected socket address is appropriate given the current context.

There's one more place to reference our new code to make sure the module executes it. We need to update module context:

```c
static ngx_http_module_t ngx_http_address_parser_module_ctx = {
  ngx_http_address_parser_module_add_variables,   /* preconfiguration */
  ngx_http_address_parser_module_init,            /* postconfiguration */
  NULL,                                           /* create main configuration */
  NULL,                                           /* init main configuration */
  NULL,                                           /* create server configuration */
  NULL,                                           /* merge server configuration */
  ngx_http_address_parser_module_create_loc_conf, /* create location configuration */
  ngx_http_address_parser_module_merge_loc_conf   /* merge location configuration */
};

Note the addition of our new function into the `preconfiguration` section of the module context. This is all that is necessary to make our variable available. In order to prevent the module from acting on the request and adding a header to the response, we need to cull the original code from the module handler:

```c
static ngx_int_t ngx_http_address_parser_module_handler(ngx_http_request_t *r) {
  if (r->main->internal) {
    return NGX_DECLINED;
  }

  return NGX_OK;
}
```

Nothing left to speak of here. There are a couple additional tricks we could do to completely remove this handler from the equation, but this is good enough for now. When you compile and run your tests you will be greeted with a large series of failures. This is because we aren't explicitly setting the header, nor are we returning 400 if it's not able to derive the address. I won't list out every single test change here. If you want to see the complete set you can find them [here](https://github.com/abedra/nginx_remote_address_example/blob/master/t/enabled.t). To add the header we will use the following configuration:

```fundamental
add_header X-Derived-Address $derived_address;
```

To return a 400 if the header is not set:

```fundamental
if ($derived_address = '') {
  return 400;
}
```

A complete updated test looks like:

```fundamental
=== TEST 2: Module enabled, XFF provided, one address
--- config
location = /t {
  address_parser on;
  add_header X-Derived-Address $derived_address;
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

A quick update to all of our tests shows the module still provides the necessary information without injecting any opinion on what should happen to the request as a result and more closely represents how a real world provider of this type of information should behave.

## Wrap-Up

While this post aimed to explain how to properly derive the IP address of a requster from the perspective of an HTTP server, it was also a complete example of how to write a custom NGINX module in C from scratch, as well as how to test drive it and really, all of your NGINX configurations. I feel that when it comes to discussing edge proxy behavior that the idea of stability and performance must be backed up at all times. Using the NGINX API and underlying server is a great foundation, and writing the module in C provides the ability to do so in the fastest way possible with the given tools.

You might still be wondering what else you could do with a tool like this other than basic load shedding. There are myriad options available once an actor has been identified including geoip restriction, consistent hash load balancing, and many others. I hope you have a new found appreciation for the detail that and weight that such a seemingly simple problem carries when introduced to the complexity of modern web application infrastructure.