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
