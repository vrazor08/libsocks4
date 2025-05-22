#ifndef URING_HELPERS_H
#define URING_HELPERS_H

#include <sys/socket.h>
#include <liburing.h>
#include <netinet/in.h>

#include "socks4.h"

void add_accept_req(int fd, struct client_t req, struct io_uring *ring);

void add_recv_req(int fd, struct client_t req, unsigned short bgid, struct io_uring *ring, unsigned int flags);

void add_connect_req(struct client_t req, struct sockaddr_in *client_dst, socklen_t addr_len, struct io_uring *ring, unsigned int flags);

void add_send_req(int fd, struct client_t req, char *send_buf, size_t send_len, struct io_uring *ring, unsigned int flags);

void add_link_timeout_req(struct client_t req, struct __kernel_timespec *ts, struct io_uring *ring);

void add_recv_req_with_timeout(int fd, struct client_t req, unsigned short bgid, struct __kernel_timespec *ts, struct io_uring *ring);

void add_connect_req_with_timeout(struct client_t req, struct sockaddr_in *client_dst, socklen_t addr_len, struct __kernel_timespec *ts, struct io_uring *ring);

void add_send_req_with_timeout(int fd, struct client_t req,  char *send_buf, size_t send_len, struct __kernel_timespec *ts, struct io_uring *ring);

void add_provide_buf(struct io_uring_buf_ring *br, char bufs[BUFFERS_COUNT][MAX_MESSAGE_LEN], __u16 bid);

#endif
