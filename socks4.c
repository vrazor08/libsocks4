#include <arpa/inet.h>
#include <assert.h>
#include <liburing.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>

#include "socks4.h"
#include "err.h"
#include "uring_helpers.h"

const int yes = 1;
const char success_ans[] = {0, 90, 0, 0, 0, 0, 0, 0};
int set_nonblocking(int fd);

static inline void recv_eq_0(client_t *req, struct io_uring *ring, struct io_uring_cqe *cqe, char* msg) {
  // TODO: don't close two fds close only one fd
  close(req->client_proxing_fd);
  close(req->client_fd);
  printf("%sexit=0, closed client_proxing_fd: %d, client_fd: %d\n", msg, req->client_proxing_fd, req->client_fd);
  free(req);
  io_uring_cqe_seen(ring, cqe);
}

int setup_listening_socket(struct socks4_server* server) {
  int fd = server->server_fd;
  if (bind(fd, (struct sockaddr *)&server->server_addr, sizeof(server->server_addr)) == -1) close_bail(fd, log_msg"bind");
  if (listen(fd, SOMAXCONN) == -1) close_bail(fd, log_msg"listen");
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) close_bail(fd, log_msg"SO_REUSEADDR");
  if (io_uring_queue_init(QUEUE_DEPTH, &server->ring, 0) < 0) close_bail(fd, log_msg"io_uring_queue_init");
  return 0;
}

int handle_client_req(client_t* req, struct sockaddr_in* sin) {
  if (req->recv_len < 3 || req->recv_len > 30) bail(log_msg"uncorrect recv_len");
  if (req->recv_buf[0] == SOCKS4_VER) {
    if (req->recv_buf[1] != SOCKS4_CONNECT_COMMAD && req->recv_buf[1] != SOCKS4_BIND_COMMAND)
      bail(log_msg"unknown socks4 command");
    int port = htons(ANTOHS(req->recv_buf, 2));
    memcpy(&sin->sin_addr.s_addr, req->recv_buf+4, 4);
    sin->sin_port = port;
    sin->sin_family = AF_INET;
  } else bail(log_msg"unknown socks version");
  return 0;
}

int handle_cons(struct socks4_server* server) {
  int client_fd;
  int fd = server->server_fd;
  client_t *req;
  client_t *new_req, *new_req2;
  char *recv_buf = (char*)malloc(BUF_SIZE);
  char *proxy_to_recv_buf = (char*)malloc(BUF_SIZE);
  memset(recv_buf, 0, BUF_SIZE);
  struct sockaddr_in client_addr;
  socklen_t client_addr_len = sizeof(client_addr);
  add_accept_req(fd, &client_addr, &client_addr_len, &server->ring);
  for (;;) {
    int ret = io_uring_wait_cqe(&server->ring, &server->cqe);
    req = (client_t*)server->cqe->user_data;
    if (ret < 0) close_bail(fd, log_msg"io_uring_wait_cqe");
    if (server->cqe->res < 0) {
      fprintf(stderr, log_msg"%s for event: %d\n", strerror(-server->cqe->res), req->state);
      fprintf(stderr, log_msg"%d\n", -server->cqe->res);
      if (-server->cqe->res == 104) {
        free(req);
        io_uring_cqe_seen(&server->ring, server->cqe);
        continue;
      }
      // TODO: Don't return form function if error was got
      goto end_with_err;
    }
    // TODO: currently it doesn't work because we need recv from client and from proxy_client and packets can be send from them
    // twice. Need spawn thread or capture several events concurrently
    switch (req->state) {
      case ACCEPT:
        client_fd = server->cqe->res;
        if (setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) < 0) close_bail(client_fd, log_msg"TCP_NODELAY");
        if (setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, server->recv_timeout, sizeof(struct timeval)) < 0)
          close_bail(client_fd, log_msg"SO_RCVTIMEO");
        add_accept_req(fd, &client_addr, &client_addr_len, &server->ring);
        new_req = (client_t*)malloc(sizeof(client_t));
        new_req->client_fd = client_fd;
        new_req->recv_buf = recv_buf;
        new_req->recv_len = BUF_SIZE;
        new_req->state = FIRST_READ;
        add_recv_req(client_fd, new_req, &server->ring);
        free(req);
        printf(log_msg"accept fd: %d\n", client_fd);
        break;
      case FIRST_READ:
        if (!server->cqe->res) {
          recv_eq_0(req, &server->ring, server->cqe, log_msg);
          continue;
        }
        printf(log_msg"first read from client: %d\n", server->cqe->res);
        struct sockaddr_in* client_dst = malloc(sizeof(struct sockaddr_in));
        memset(client_dst, 0, sizeof(&client_dst));
        req->recv_len = server->cqe->res;
        if (handle_client_req(req, client_dst) == -1) { free(req->recv_buf); goto end_with_err; }
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_dst->sin_addr, dst_ip_str, INET_ADDRSTRLEN);
        printf(log_msg"Connect to dst: %s:%d\n", dst_ip_str, client_dst->sin_port);
        server->state = con_to_dst;
        int con_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (con_fd == -1) bail("client socket creation failed");
        if (setsockopt(con_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) < 0) close_bail(con_fd, log_msg"TCP_NODELAY");
        if (setsockopt(con_fd, SOL_SOCKET, SO_RCVTIMEO, server->recv_timeout, sizeof(struct timeval)) < 0)
          close_bail(con_fd, log_msg"SO_RCVTIMEO");
        printf(log_msg"client_proxing_fd: %d\n", con_fd);
        client_t *new_req = (client_t*)malloc(sizeof(client_t));
        new_req->client_proxing_fd = con_fd;
        new_req->state = CONNECT;
        new_req->client_fd = req->client_fd;
        // new_req->recv_buf = req->recv_buf;
        add_connect_req(new_req, client_dst, client_addr_len, &server->ring);

        free(req);
        puts(log_msg"read gol");
        break;
      case CONNECT:
        client_fd = req->client_fd;
        new_req = (client_t*)malloc(sizeof(client_t));
        new_req->client_fd = client_fd;
        new_req->client_proxing_fd = req->client_proxing_fd;
        new_req->send_buf = (char*)success_ans;
        new_req->send_buf_len = sizeof(success_ans);
        new_req->state = WRITE_TO_CLIENT_AFTER_CONNECT;
        add_send_req(client_fd, new_req, &server->ring);
        puts(log_msg"Connect req");
        free(req);
        break;
      case WRITE_TO_CLIENT_AFTER_CONNECT:
        client_fd = req->client_fd;
        new_req = (client_t*)malloc(sizeof(client_t));
        new_req->client_fd = client_fd;
        new_req->client_proxing_fd = req->client_proxing_fd;
        new_req->recv_buf = recv_buf;
        new_req->recv_len = BUF_SIZE;
        new_req->state = READ_FROM_CLIENT;
        add_recv_req(client_fd, new_req, &server->ring);

        new_req2 = (client_t*)malloc(sizeof(client_t));
        new_req2->client_fd = client_fd;
        new_req2->client_proxing_fd = req->client_proxing_fd;
        new_req2->recv_buf = proxy_to_recv_buf;
        new_req2->recv_len = BUF_SIZE;
        new_req2->state = READ_FROM_CLIENT_PROXING;
        add_recv_req(req->client_proxing_fd, new_req2, &server->ring);

        puts(log_msg"WRITE_TO_CLIENT_AFTER_CONNECT");
        free(req);
        break;
      case WRITE_TO_CLIENT:
        client_fd = req->client_fd;
        new_req2 = (client_t*)malloc(sizeof(client_t));
        new_req2->client_fd = client_fd;
        new_req2->client_proxing_fd = req->client_proxing_fd;
        new_req2->recv_buf = proxy_to_recv_buf;
        new_req2->recv_len = BUF_SIZE;
        new_req2->state = READ_FROM_CLIENT_PROXING;
        add_recv_req(req->client_proxing_fd, new_req2, &server->ring);
        puts(log_msg"WRITE_TO_CLIENT");
        free(req);
        break;
      case READ_FROM_CLIENT:
        printf(log_msg"READ_FROM_CLIENT: %d\n", server->cqe->res);
        if (!server->cqe->res) {
          recv_eq_0(req, &server->ring, server->cqe, log_msg);
          continue;
        }
        client_fd = req->client_fd;
        new_req = (client_t*)malloc(sizeof(client_t));
        new_req->send_buf = recv_buf;
        new_req->send_buf_len = server->cqe->res;
        new_req->state = WRITE_TO_CLIENT_PROXING;
        new_req->client_fd = client_fd;
        new_req->client_proxing_fd = req->client_proxing_fd;
        add_send_req(new_req->client_proxing_fd, new_req, &server->ring);
        free(req);
        break;
      case WRITE_TO_CLIENT_PROXING:
        client_fd = req->client_fd;
        new_req = (client_t*)malloc(sizeof(client_t));
        new_req->client_fd = client_fd;
        new_req->client_proxing_fd = req->client_proxing_fd;
        new_req->recv_buf = recv_buf;
        new_req->recv_len = BUF_SIZE;
        new_req->state = READ_FROM_CLIENT;
        add_recv_req(client_fd, new_req, &server->ring);
        puts(log_msg"WRITE_TO_CLIENT_PROXING");
        free(req);
        break;
      case READ_FROM_CLIENT_PROXING:
        printf(log_msg"READ_FROM_CLIENT_PROXING: %d\n", server->cqe->res);
        if (!server->cqe->res) {
          recv_eq_0(req, &server->ring, server->cqe, log_msg);
          continue;
        }
        new_req = (client_t*)malloc(sizeof(client_t));
        new_req->send_buf = req->recv_buf;
        new_req->send_buf_len = server->cqe->res;
        new_req->client_fd = req->client_fd;
        new_req->client_proxing_fd = req->client_proxing_fd;
        new_req->state = WRITE_TO_CLIENT;
        add_send_req(req->client_fd, new_req, &server->ring);
        free(req);
        break;
    }
    io_uring_cqe_seen(&server->ring, server->cqe);
  }
  end_with_err:;
    io_uring_cqe_seen(&server->ring, server->cqe);
    puts(log_msg"err");
    free(req);
    return -1;
}

int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) return -1;
  flags |= O_NONBLOCK;
  if (fcntl(fd, F_SETFL, flags) == -1) return -1;
  return 0;
}
