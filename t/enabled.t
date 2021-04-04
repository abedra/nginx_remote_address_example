use Test::Nginx::Socket 'no_plan';

no_shuffle();
run_tests();

__DATA__
=== TEST 1: Module enabled, no XFF provided, no custom IP header
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

=== TEST 2: Module enabled, XFF provided, one address
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

