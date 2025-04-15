#include <liburing.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "uring_helpers.h"
#include "socks4.h"

void add_accept_req(int fd, client_t *req, struct io_uring *ring) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_multishot_accept(sqe, fd, NULL, NULL, 0);
  io_uring_sqe_set_data(sqe, (void*)req);
  io_uring_submit(ring);
}

void add_connect_req(client_t *req, struct sockaddr_in *client_dst, socklen_t addr_len, struct io_uring *ring) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_connect(sqe, req->client_proxing_fd, (struct sockaddr*)client_dst, addr_len);
  io_uring_sqe_set_data(sqe, (void*)req);
  io_uring_submit(ring);
}

void add_recv_req(int fd, client_t *req, struct io_uring *ring) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_recv(sqe, fd, NULL, MAX_MESSAGE_LEN, 0);
  io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
  sqe->buf_group = 0;

  io_uring_sqe_set_data(sqe, (void*)req);
  io_uring_submit(ring);
}

int add_send_req(int fd, client_t *req, struct io_uring *ring) {
  struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
  io_uring_prep_send(sqe, fd, req->send_buf, req->send_len, 0);
  io_uring_sqe_set_data(sqe, (void*)req);
  io_uring_submit(ring);
  return 0;
}

void add_provide_buf(struct io_uring_buf_ring *br, char bufs[BUFFERS_COUNT][MAX_MESSAGE_LEN], __u16 bid) {
  io_uring_buf_ring_add(br, bufs[bid], MAX_MESSAGE_LEN, bid, io_uring_buf_ring_mask(BUFFERS_COUNT), 0);
	io_uring_buf_ring_advance(br, 1);
#ifdef SOCKS_DEBUG
  if (bufs[bid][0] == 2) { printf("try to provide buffer: bufs[%u] but that is already provided\n", bid); }
#endif
}
