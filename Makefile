CFLAGS = -O2 -Wall -Wextra -pedantic

default: all

.PHONY: all debug clean run
all: build/libsocks4.a build/libsocks4.so debug examples/main examples/test-main

build/:
	@mkdir -p build

debug:
	cc -I. examples/main.c socks4.c uring_helpers.c -o examples/socks4-debug -DSOCKS_DEBUG $(CFLAGS) -ggdb -luring

build/uring_helpers.o: uring_helpers.c uring_helpers.h socks4.h
	cc uring_helpers.c -c -o build/uring_helpers.o -fPIC $(CFLAGS)

build/socks4.o: socks4.c socks4.h uring_helpers.h err.h
	cc socks4.c -c -o build/socks4.o -fPIC $(CFLAGS)

build/libsocks4.a: build/socks4.o build/uring_helpers.o
	@ar -rcs build/libsocks4.a build/socks4.o build/uring_helpers.o

build/libsocks4.so: build/socks4.o build/uring_helpers.o
	cc -I. -o build/libsocks4.so build/socks4.o build/uring_helpers.o -shared -fPIC $(CFLAGS)

examples/main: examples/main.c build/libsocks4.a
	cc -I. -o examples/main examples/main.c $(CFLAGS) build/libsocks4.a -luring

examples/test-main: examples/main.c build/libsocks4.a
	cc -I. -o examples/test-main examples/main.c $(CFLAGS) build/libsocks4.a -DSOCKS_TEST -luring

run: examples/test-main
	ulimit -n 8192 && ./examples/test-main

clean:
	@rm -f socks4-debug build/*
	@rm -f examples/main examples/socks4-debug
