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
const char success_socks_ans  [] = {0, 90, 0, 0, 0, 0, 0, 0};
const char unsuccess_socks_ans[] = {0, 91, 0, 0, 0, 0, 0, 0};


static inline void prep_sockets(client_t *old_req, client_t *new_req) {
  new_req->client_fd = old_req->client_fd;
  new_req->client_proxing_fd = old_req->client_proxing_fd;
}

static inline void prep_new_send_req(client_t *old_req, client_t *new_req, int send_buf_len) {
  new_req->send_buf = old_req->recv_buf;
  new_req->send_buf_len = send_buf_len;
}

static inline void prep_new_recv_req(client_t *new_req, char *recv_buf) {
  new_req->recv_buf = recv_buf;
  new_req->recv_len = BUF_SIZE;
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
  int fd = server->server_fd;
  client_t *req, *req_read_client, *req_read_client_proxing;
  char *recv_buf = (char*)malloc(BUF_SIZE); // TODO: maybe free this somewhere
  memset(recv_buf, 0, BUF_SIZE);
  struct sockaddr_in proxy_client_dst, client_addr = {0};
  socklen_t client_addr_len = sizeof(client_addr);
  add_accept_req(fd, &client_addr, client_addr_len, &server->ring);
  for (;;) {
    int ret = io_uring_wait_cqe(&server->ring, &server->cqe);
    req = (client_t*)server->cqe->user_data;
    if (ret < 0) bail(log_msg"io_uring_wait_cqe");
    if (server->cqe->res < 0) {
      fprintf(stderr, log_msg"%s for event: %d\n", strerror(-server->cqe->res), req->state);
      fprintf(stderr, log_msg"-server->cqe->res=%d\n", -server->cqe->res);
      free(req);
      io_uring_cqe_seen(&server->ring, server->cqe);
      continue;
    }

    switch (req->state) {
      case ACCEPT:
        req->client_fd = server->cqe->res;
        if (setsockopt(req->client_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) < 0)
          close_bail(req->client_fd, log_msg"TCP_NODELAY");
        add_accept_req(fd, &client_addr, client_addr_len, &server->ring);
        req_read_client = (client_t*)malloc(sizeof(client_t));
        req_read_client->client_fd = req->client_fd;
        prep_new_recv_req(req_read_client, recv_buf);
        req_read_client->state = FIRST_READ;
        add_recv_req(req->client_fd, req_read_client, &server->ring);
        printf(log_msg"accept fd: %d\n", req->client_fd);
        free(req);
        break;
      case FIRST_READ:
        if (!server->cqe->res) {
          close(req->client_fd);
          printf(log_msg"exit=0, closed client_fd: %d\n", req->client_fd);
          free(req);
          break;
        }
        printf(log_msg"first read from client: %d\n", server->cqe->res);

        req->recv_len = server->cqe->res;
        req_read_client = (client_t*)malloc(sizeof(client_t));
        req_read_client->client_fd = req->client_fd;
        if (handle_client_req(req, &proxy_client_dst) == -1) {
          req_read_client->state = WRITE_ERR_TO_CLIENT;
          req_read_client->send_buf = (char*)unsuccess_socks_ans;
          req_read_client->send_buf_len = sizeof(unsuccess_socks_ans);
          add_send_req(req->client_fd, req_read_client, &server->ring);
          break;
        }
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &proxy_client_dst.sin_addr, dst_ip_str, INET_ADDRSTRLEN);
        printf(log_msg"Connect to dst: %s:%d\n", dst_ip_str, proxy_client_dst.sin_port);
        server->state = con_to_dst;
        int con_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (con_fd == -1) bail("client socket creation failed");
        if (setsockopt(con_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) < 0) close_bail(con_fd, log_msg"TCP_NODELAY");
        printf(log_msg"client_proxing_fd: %d\n", con_fd);
        req_read_client->client_proxing_fd = con_fd;
        req_read_client->state = CONNECT;
        add_connect_req(req_read_client, &proxy_client_dst, client_addr_len, &server->ring);
        free(req);
        break;
      case CONNECT:
        req_read_client = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, req_read_client);
        req_read_client->send_buf = (char*)success_socks_ans;
        req_read_client->send_buf_len = sizeof(success_socks_ans);
        req_read_client->state = WRITE_TO_CLIENT_AFTER_CONNECT;
        add_send_req(req->client_fd, req_read_client, &server->ring);
        puts(log_msg"Connect req");
        free(req);
        break;
      case WRITE_ERR_TO_CLIENT:
        fprintf(stderr, log_msg"uncorrect first socks4 send from client: %d\n", req->client_fd);
        close(req->client_fd);
        free(req);
        break;
      case WRITE_TO_CLIENT_AFTER_CONNECT:
        req_read_client = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, req_read_client);
        prep_new_recv_req(req_read_client, recv_buf);
        req_read_client->state = READ_FROM_CLIENT;
        add_recv_req(req->client_fd, req_read_client, &server->ring);

        req_read_client_proxing = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, req_read_client_proxing);
        prep_new_recv_req(req_read_client_proxing, recv_buf);
        req_read_client_proxing->state = READ_FROM_CLIENT_PROXING;
        add_recv_req(req->client_proxing_fd, req_read_client_proxing, &server->ring);

        puts(log_msg"WRITE_TO_CLIENT_AFTER_CONNECT");
        free(req);
        break;
      case WRITE_TO_CLIENT:
        req_read_client_proxing = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, req_read_client_proxing);
        prep_new_recv_req(req_read_client_proxing, recv_buf);
        req_read_client_proxing->state = READ_FROM_CLIENT_PROXING;
        add_recv_req(req->client_proxing_fd, req_read_client_proxing, &server->ring);
        puts(log_msg"WRITE_TO_CLIENT");
        free(req);
        break;
      case READ_FROM_CLIENT:
        printf(log_msg"READ_FROM_CLIENT: %d\n", server->cqe->res);
        if (!server->cqe->res) {
          close(req->client_fd);
          printf(log_msg"exit=0, closed client_fd: %d\n", req->client_fd);
          free(req);
          break;
        }
        req_read_client = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, req_read_client);
        req_read_client->state = WRITE_TO_CLIENT_PROXING;
        prep_new_send_req(req, req_read_client, server->cqe->res);
        add_send_req(req_read_client->client_proxing_fd, req_read_client, &server->ring);
        free(req);
        break;
      case WRITE_TO_CLIENT_PROXING:
        req_read_client = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, req_read_client);
        prep_new_recv_req(req_read_client, recv_buf);
        req_read_client->state = READ_FROM_CLIENT;
        add_recv_req(req->client_fd, req_read_client, &server->ring);
        puts(log_msg"WRITE_TO_CLIENT_PROXING");
        free(req);
        break;
      case READ_FROM_CLIENT_PROXING:
        printf(log_msg"READ_FROM_CLIENT_PROXING: %d\n", server->cqe->res);
        if (!server->cqe->res) {
          close(req->client_proxing_fd);
          printf(log_msg"exit=0, closed client_proxing_fd: %d\n", req->client_proxing_fd);
          free(req);
          break;
        }
        req_read_client = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, req_read_client);
        prep_new_send_req(req, req_read_client, server->cqe->res);
        req_read_client->state = WRITE_TO_CLIENT;
        add_send_req(req->client_fd, req_read_client, &server->ring);
        free(req);
        break;
    }
    io_uring_cqe_seen(&server->ring, server->cqe);
  }
  return 0;
}
