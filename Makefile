export PATH := $(shell pwd)/build/nginx/sbin:$(PATH)

.PHONY: test
test:
	redis-cli flushdb
	prove t/*.t

compile:
	script/bootstrap compile

bootstrap:
	script/bootstrap

clean:
	script/bootstrap clean

start:
	build/nginx/sbin/nginx

stop:
	build/nginx/sbin/nginx -s stop

reload:
	build/nginx/sbin/nginx -s reload

.PHONY: clean start stop reload