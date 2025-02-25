#include <liburing.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <assert.h>

#include "uring_helpers.h"
#include "socks4.h"

void add_accept_req(int fd,
  struct sockaddr_in* client_addr,
  socklen_t addr_len,
  struct io_uring* ring
) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_accept(sqe, fd, (struct sockaddr*)client_addr, &addr_len, 0);
  client_t* req = malloc(sizeof(client_t));
  req->state = ACCEPT;
  io_uring_sqe_set_data(sqe, (void*)req);
  io_uring_submit(ring);
}

void add_connect_req(client_t *req, struct sockaddr_in* client_dst, socklen_t addr_len, struct io_uring* ring) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_connect(sqe, req->client_proxing_fd, (struct sockaddr*)client_dst, addr_len);
  io_uring_sqe_set_data(sqe, (void*)req);
  io_uring_submit(ring);
}

void add_recv_req(int fd, client_t* req, struct io_uring* ring) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_recv(sqe, fd, (void*)req->recv_buf, req->recv_len, 0);
  io_uring_sqe_set_data(sqe, (void*)req);
  io_uring_submit(ring);
}

int add_send_req(int fd, client_t *req, struct io_uring *ring) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_send(sqe, fd, req->send_buf, req->send_buf_len, 0);
  io_uring_sqe_set_data(sqe, (void*)req);
  io_uring_submit(ring);
  return 0;
}
