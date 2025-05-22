#include <liburing.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>

#include "uring_helpers.h"
#include "socks4.h"

static struct io_uring_sqe *get_sqe(struct io_uring *ring) {
  struct io_uring_sqe *sqe;
  do {
    sqe = io_uring_get_sqe(ring);
    if (sqe) break;
    io_uring_submit(ring);
  } while (1);
  return sqe;
}

void add_accept_req(int fd, struct client_t req, struct io_uring *ring) {
  struct io_uring_sqe *sqe = get_sqe(ring);
  io_uring_prep_multishot_accept(sqe, fd, NULL, NULL, 0);
  io_uring_sqe_set_data64(sqe, req.val);
}

void add_connect_req(struct client_t req, struct sockaddr_in *client_dst, socklen_t addr_len, struct io_uring *ring, unsigned int flags) {
  struct io_uring_sqe *sqe = get_sqe(ring);
  io_uring_prep_connect(sqe, req.target_fd, (struct sockaddr*)client_dst, addr_len);
  io_uring_sqe_set_flags(sqe, flags);
  io_uring_sqe_set_data64(sqe, req.val);
}

void add_recv_req(int fd, struct client_t req, unsigned short bgid, struct io_uring *ring, unsigned int flags) {
  struct io_uring_sqe *sqe = get_sqe(ring);
  io_uring_prep_recv(sqe, fd, NULL, MAX_MESSAGE_LEN, 0);
  io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT|flags);
  sqe->buf_group = bgid;
  io_uring_sqe_set_data64(sqe, req.val);
}

void add_send_req(int fd, struct client_t req, char *send_buf, size_t send_len, struct io_uring *ring, unsigned int flags) {
  struct io_uring_sqe *sqe = get_sqe(ring);
  io_uring_prep_send(sqe, fd, send_buf, send_len, 0);
  io_uring_sqe_set_flags(sqe, flags);
  io_uring_sqe_set_data64(sqe, req.val);
}

void add_link_timeout_req(struct client_t req, struct __kernel_timespec *ts, struct io_uring *ring) {
  struct client_t timeout_req = req;
  struct io_uring_sqe *timeout_sqe = get_sqe(ring);
  io_uring_prep_link_timeout(timeout_sqe, ts, 0);
  timeout_req.state = TIMEOUT;
  io_uring_sqe_set_data64(timeout_sqe, timeout_req.val);
}

void add_recv_req_with_timeout(int fd, struct client_t req, unsigned short bgid, struct __kernel_timespec *ts, struct io_uring *ring) {
  add_recv_req(fd, req, bgid, ring, IOSQE_IO_LINK);
  add_link_timeout_req(req, ts, ring);
}

void add_connect_req_with_timeout(struct client_t req, struct sockaddr_in *client_dst, socklen_t addr_len, struct __kernel_timespec *ts, struct io_uring *ring) {
  add_connect_req(req, client_dst, addr_len, ring, IOSQE_IO_LINK);
  add_link_timeout_req(req, ts, ring);
}

void add_send_req_with_timeout(int fd, struct client_t req,  char *send_buf, size_t send_len, struct __kernel_timespec *ts, struct io_uring *ring) {
  add_send_req(fd, req, send_buf, send_len, ring, IOSQE_IO_LINK);
  add_link_timeout_req(req, ts, ring);
}

void add_provide_buf(struct io_uring_buf_ring *br, char bufs[BUFFERS_COUNT][MAX_MESSAGE_LEN], __u16 bid) {
  io_uring_buf_ring_add(br, bufs[bid], MAX_MESSAGE_LEN, bid, io_uring_buf_ring_mask(BUFFERS_COUNT), 0);
  io_uring_buf_ring_advance(br, 1);
#ifdef SOCKS_DEBUG
  if (bufs[bid][0] == 2) { printf("try to provide buffer: bufs[%u] but that is already provided\n", bid); }
#endif
}
