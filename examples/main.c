#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../socks4.h"
#include "../err.h"

const char *host = "127.0.0.2";
#define PORT 6969

void logger(logging_client_t req, struct socks4_server *server) {
  char dst_ip_str[INET_ADDRSTRLEN];
  struct sockaddr_in proxy_client_dst;
  switch (req.state) {
    case ACCEPT:
      printf(log_msg"accept fd: %d\n", req.client_fd);
      printf(log_msg"free buffers count: %d\n", io_uring_buf_ring_available(&server->ring, server->br, server->bgid));
      break;

    case FIRST_READ:
      if (server->cqe->res <= 0)
        printf("\n"log_msg"server->cqe->res=0, closed client_fd: %d\n", req.client_fd);
      printf("\n"log_msg"first read from client: %d\n", req.client_fd);
      printf(log_msg"server->cqe->flags >> IORING_CQE_BUFFER_SHIFT = %u\n", server->cqe->flags >> IORING_CQE_BUFFER_SHIFT);
      break;

    case CONNECT:
      proxy_client_dst = connects[req.client_fd];
      inet_ntop(AF_INET, &proxy_client_dst.sin_addr, dst_ip_str, INET_ADDRSTRLEN);
      printf(log_msg"Connect to dst: %s:%u\n", dst_ip_str, htons(proxy_client_dst.sin_port));
      printf(log_msg"Connect req, client_fd: %d, target_fd: %d\n", req.client_fd, req.target_fd);
      break;

    case WRITE_ERR_TO_CLIENT:
      break;

    case WRITE_TO_CLIENT_AFTER_CONNECT:
      printf(log_msg"WRITE_TO_CLIENT_AFTER_CONNECT, client_fd: %d, target_fd: %d\n", req.client_fd, req.target_fd);
      break;

    case WRITE_TO_CLIENT:
      printf(log_msg"WRITE_TO_CLIENT, client_fd: %d, target_fd: %d\n", req.client_fd, req.target_fd);
      break;

    case READ_FROM_CLIENT:
      if (server->cqe->res <= 0)
        printf(log_msg"exit=0, closed target_fd: %d, add_provide_buf: %u\n", req.target_fd, server->cqe->flags >> IORING_CQE_BUFFER_SHIFT);
      printf(log_msg"READ_FROM_CLIENT: %d, %d bytes\n", req.client_fd, server->cqe->res);
      break;

    case WRITE_TO_CLIENT_PROXING:
      printf(log_msg"WRITE_TO_CLIENT_PROXING, client_fd: %d, target_fd: %d\n", req.client_fd, req.target_fd);
      break;

    case READ_FROM_CLIENT_PROXING:
      printf(log_msg"READ_FROM_CLIENT_PROXING: %d, %d bytes\n", req.target_fd, server->cqe->res);
      if (server->cqe->res <= 0)
        printf(log_msg"exit=0, closed client_fd: %d, add_provide_buf: %u\n", req.client_fd, server->cqe->flags >> IORING_CQE_BUFFER_SHIFT);
      break;
    case TIMEOUT:
      printf(log_msg"TIMEOUT for client_fd: %d, target_fd: %d\n", req.client_fd, req.target_fd);
      break;
  }
}

int main(void) {
  printf(log_msg"starting on: %s:%d\n", host, PORT);
  dbg(puts(log_msg"debug mode is enable"));
  int rv;
  struct socks4_server server = {0};
  struct sockaddr_in addr = {0};
#ifdef SOCKS_TEST
  puts(log_msg"test mode is enable");
  struct __kernel_timespec recv_ts = {.tv_sec = 3, .tv_nsec = 0};
  struct __kernel_timespec con_ts =  {.tv_sec = 3, .tv_nsec = 0};
  struct __kernel_timespec send_ts =  {.tv_sec = 3, .tv_nsec = 0};
#else
  struct __kernel_timespec recv_ts = {.tv_sec = 60*3, .tv_nsec = 0};
  struct __kernel_timespec con_ts  = {.tv_sec = 60*3, .tv_nsec = 0};
  struct __kernel_timespec send_ts = {.tv_sec = 60*1, .tv_nsec = 0};
#endif
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(host);
  addr.sin_port = htons(PORT);
  server.server_addr = addr;
  server.recv_timeout = &recv_ts;
  server.connect_timeout = &con_ts;
  server.send_timeout = &send_ts;
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return 1;
  server.server_fd = fd;
  if (setup_listening_socket(&server) != 0) {
    close(server.server_fd);
    return 1;
  }
  if (socks4_setup_io_uring_queue(&server) != 0) {
    close(server.server_fd);
    return 1;
  }
#ifdef SOCKS_DEBUG
  rv = handle_cons(&server, logger, ALL_EVENT_TYPES);
#else
  rv = handle_cons(&server, 0, 0);
#endif
  io_uring_queue_exit(&server.ring);
  close(server.server_fd);
  return rv;
}
