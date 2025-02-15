// gcc -Wall -Wextra -O2 main.c socks4.c uring_helpers.c -o socks4 -luring
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socks4.h"

const char* host = "127.0.0.2";
#define PORT 6969

int main(void) {
  printf("starting on: %s:%d\n", host, PORT);
  struct socks4_server server;
  struct sockaddr_in addr;
  struct timeval recv_timeout = { .tv_sec = 2, .tv_usec = 0};
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(host);
  addr.sin_port = htons(PORT);
  server.server_addr = addr;
  server.recv_timeout = &recv_timeout;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return 1;
  server.server_fd = fd;
  if (setup_listening_socket(&server) != 0) return 1;
  if (handle_cons(&server) != 0) { close(server.server_fd); return 1; }
  close(server.server_fd);
  io_uring_queue_exit(&server.ring);
  return 0;
}
