#ifndef URING_HELPERS_H
#define URING_HELPERS_H

#include <sys/socket.h>
#include <liburing.h>
#include <netinet/in.h>

#include "err.h"
#include "socks4.h"

void add_accept_req(int fd,
  struct sockaddr_in *client_addr,
  socklen_t addr_len,
  struct io_uring *ring
);

void add_recv_req(int fd, client_t *req, struct io_uring *ring);
/// connect using con_fd to client_dst, client_fd is fd given from accept and it need to put it into next state
///
/// TODO: get client_fd from old req
void add_connect_req(client_t *req, struct sockaddr_in* client_dst, socklen_t addr_len, struct io_uring* ring);
int add_send_req(int fd, client_t *req, struct io_uring *ring);

#endif
