#ifndef URING_HELPERS_H
#define URING_HELPERS_H

#include <sys/socket.h>
#include <liburing.h>
#include <netinet/in.h>

#include "socks4.h"

void add_accept_req(int fd, client_t *req, struct io_uring *ring);
void add_recv_req(int fd, client_t *req, struct io_uring *ring);
void add_connect_req(client_t *req, struct sockaddr_in *client_dst, socklen_t addr_len, struct io_uring *ring);
int add_send_req(int fd, client_t *req, struct io_uring *ring);
void add_provide_buf(struct io_uring_buf_ring *br, char bufs[BUFFERS_COUNT][MAX_MESSAGE_LEN], __u16 bid);

#endif
