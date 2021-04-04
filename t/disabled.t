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
