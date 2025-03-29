socks:
	gcc main.c socks4.c uring_helpers.c -o socks4 -O2 -Wall -Wextra -pedantic -luring

debug:
	gcc main.c socks4.c uring_helpers.c -o socks4 -DSOCKS_DEBUG -O2 -Wall -Wextra -pedantic -ggdb -luring
