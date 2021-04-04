export PATH := $(shell pwd)/build/nginx/sbin:$(PATH)

default: compile

test:
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

.PHONY: clean start stop reload test