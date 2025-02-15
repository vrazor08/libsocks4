socks:
	gcc main.c socks4.c uring_helpers.c -o socks4 -O2 -Wall -Wextra -pedantic -ggdb -luring
