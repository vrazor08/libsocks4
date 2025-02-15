#include <liburing.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <assert.h>

#include "uring_helpers.h"
#include "socks4.h"

void add_accept_req(int fd,
  struct sockaddr_in* client_addr,
  socklen_t* addr_len,
  struct io_uring* ring
) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_accept(sqe, fd, (struct sockaddr*)client_addr, addr_len, 0);
  client_t* req = malloc(sizeof(client_t));
  req->state = ACCEPT;
  io_uring_sqe_set_data(sqe, (void*)req);
  io_uring_submit(ring);
}

void add_connect_req(client_t *req, struct sockaddr_in* client_dst, socklen_t addr_len, struct io_uring* ring) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_connect(sqe, req->client_proxing_fd, (struct sockaddr*)client_dst, addr_len);
  // client_t* req = malloc(sizeof(client_t));
  // req->state = CONNECT;
  // req->client_proxing_fd = con_fd;
  // req->client_fd = client_fd;
  io_uring_sqe_set_data(sqe, (void*)req);
  io_uring_submit(ring);
}

void add_recv_req(int fd, client_t* req, struct io_uring* ring) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  // char* recv_buf = (char*)malloc(BUF_SIZE);
  // memset(recv_buf, 0, BUF_SIZE);
  // printf("recv_len: %lu\n", req->recv_len);
  io_uring_prep_recv(sqe, fd, (void*)req->recv_buf, req->recv_len, 0);
  // client_t* req = malloc(sizeof(client_t));
  // req->state = recv_state;
  // req->recv_buf = recv_buf;
  // req->recv_len = recv_size;
  // req->client_fd = client_fd;
  io_uring_sqe_set_data(sqe, (void*)req);
  io_uring_submit(ring);
}

int add_send_req(int fd, client_t *req, struct io_uring *ring) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_send(sqe, fd, req->send_buf, req->send_buf_len, 0);
  // client_t* req = malloc(sizeof(client_t));
  // req->state = send_state;
  // req->client_fd = fd;
  io_uring_sqe_set_data(sqe, (void*)req);
  io_uring_submit(ring);
  return 0;
}
