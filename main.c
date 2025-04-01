#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "socks4.h"
#include "err.h"

const char* host = "127.0.0.2";
#define PORT 6969

int main(void) {
  printf(log_msg"starting on: %s:%d\n", host, PORT);
  dbg(puts(log_msg"debug mode is enable"));
  struct socks4_server server = {0};
  struct sockaddr_in addr = {0};
  struct timeval recv_timeout = { .tv_sec = 2, .tv_usec = 0};
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
  io_uring_queue_exit(&server.ring);
  close(server.server_fd);
  return 0;
}
