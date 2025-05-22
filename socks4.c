#include <arpa/inet.h>
#include <liburing.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "err.h"
#include "socks4.h"
#include "uring_helpers.h"

static const int yes = 1;
static const int syn_retries = 1;
static const char success_socks_ans  [] = {0, 90, 0, 0, 0, 0, 0, 0};
static const char unsuccess_socks_ans[] = {0, 91, 0, 0, 0, 0, 0, 0};

const char *StateStrs[] = {
  "Nothing",
  "ACCEPT",
  "READ_FROM_CLIENT",
  "READ_FROM_CLIENT_PROXING",
  "FIRST_READ",
  "WRITE_ERR_TO_CLIENT",
  "WRITE_TO_CLIENT",
  "WRITE_TO_CLIENT_AFTER_CONNECT",
  "WRITE_TO_CLIENT_PROXING",
  "CONNECT",
  "TIMEOUT",
};

const char *state_to_str(unsigned int state) {
  int i;
  for (i = 0; state > 1; state >>= 1, i++);
  return StateStrs[i+1];
}

static char bufs[BUFFERS_COUNT][MAX_MESSAGE_LEN] = {0};
struct sockaddr_in connects[MAX_CONNECTS];

static inline logging_client_t from_client_t(struct client_t req) {
  logging_client_t log_req = {0};
  prep_sockets(req, log_req);
  log_req.state = req.state;
  log_req.bid = req.bid;
  return log_req;
}

static inline void close_everything(int client_fd, int target_fd) {
  if (client_fd >= 0) {
    shutdown(client_fd, SHUT_RDWR);
    close(client_fd);
  }
  if (target_fd >= 0) {
    shutdown(target_fd, SHUT_RDWR);
    close(target_fd);
  }
}

int setup_listening_socket(struct socks4_server* server) {
  int fd = server->server_fd;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) bail(log_msg"SO_REUSEADDR");
  if (bind(fd, (struct sockaddr *)&server->server_addr, sizeof(server->server_addr)) == -1) bail(log_msg"bind");
  if (listen(fd, SOMAXCONN) == -1) bail(log_msg"listen");
  return 0;
}

int socks4_setup_io_uring_queue(struct socks4_server* server) {
  struct io_uring_params params = {0};
  params.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_CLAMP;
  params.flags |= IORING_SETUP_COOP_TASKRUN;
  params.flags |= IORING_SETUP_DEFER_TASKRUN;
  int rv = io_uring_queue_init_params(QUEUE_DEPTH, &server->ring, &params);
  if (rv) {
    fprintf(stderr, log_msg"io_uring_queue_init_params: %s\n", strerror(-rv)); // TODO: return own errno
    return -1;
  }
  struct io_uring_buf_reg reg = { 0 };
  struct io_uring_buf_ring *br;
  if (posix_memalign((void **) &br, getpagesize(), BUFFERS_COUNT * sizeof(struct io_uring_buf_ring))) {
    io_uring_queue_exit(&server->ring);
    bail(log_msg"posix_memalign");
  }
  reg.ring_addr = (unsigned long)br;
  reg.ring_entries = BUFFERS_COUNT;
  reg.bgid = server->bgid;
  rv = io_uring_register_buf_ring(&server->ring, &reg, 0);
  if (rv) {
    free(br);
    io_uring_queue_exit(&server->ring);
    fprintf(stderr, log_msg"io_uring_register_buf_ring: %s\n", strerror(-rv));
    return -1;
  }
  io_uring_buf_ring_init(br);
  for (int i = 0; i < BUFFERS_COUNT; i++) {
    io_uring_buf_ring_add(br, bufs[i], MAX_MESSAGE_LEN, i, io_uring_buf_ring_mask(BUFFERS_COUNT), i);
  }
  io_uring_buf_ring_advance(br, BUFFERS_COUNT);
  server->br = br;
  return 0;
}

int handle_client_req(char *buf, size_t buf_len, struct sockaddr_in *sin) {
  for (size_t i = 0; i<MIN_SOCKS_CONNECT_LEN; i++) {
    __builtin_prefetch(buf+i, 0, 1);
  }

  if (buf_len < MIN_SOCKS_CONNECT_LEN || buf_len > MAX_SOCKS_CONNECT_LEN) {
    fprintf(stderr, log_msg"uncorrect recv_len: %lu\n", buf_len);
    return -1;
  }
  if (buf[0] == SOCKS4_VER) {
    if (buf[1] != SOCKS4_CONNECT_COMMAD && buf[1] != SOCKS4_BIND_COMMAND) {
      fprintf(stderr, log_msg"unknown socks4 command: %u\n", buf[1]);
      return -1;
    }
    in_port_t port = htons(ANTOHS(buf, 2));
    memcpy(&sin->sin_addr.s_addr, buf+4, 4);
    sin->sin_port = port;
    sin->sin_family = AF_INET;
  } else {
    fprintf(stderr, log_msg"unknown socks version: %u, buf_len: %lu\n", buf[0], buf_len);
    return -1;
  }
  return 0;
}

int handle_cons(struct socks4_server* server, void (*handler)(logging_client_t, struct socks4_server*), event_type func_call) {
  int ret;
  int fd = server->server_fd;
  struct client_t req, client_req, target_req;
  logging_client_t log_req;
  struct client_t accept_req = { .state = ACCEPT };
  add_accept_req(fd, accept_req, &server->ring);
  for (;;) {
    ret = io_uring_submit_and_wait(&server->ring, 1);
    (void)ret;
    unsigned int head, count = 0;
    io_uring_for_each_cqe(&server->ring, head, server->cqe) {
      ++count;
      req.val = server->cqe->user_data;
      if (server->cqe->res < 0) {
        // TODO: if for state we have open fds - close them.
        if (req.state == CONNECT) {
          prep_sockets(req, client_req);
          client_req.state = WRITE_ERR_TO_CLIENT;
          add_send_req_with_timeout(req.client_fd, client_req, (char*)unsuccess_socks_ans, sizeof(unsuccess_socks_ans), server->send_timeout, &server->ring);
        // TODO: it's right for recv but not for other events
        } else if (req.state == READ_FROM_CLIENT) {
          close_everything(-1, req.target_fd);
          fprintf(stderr, log_msg"target_fd: %d was closed because recv error\n", req.target_fd);
        } else if (req.state == READ_FROM_CLIENT_PROXING) {
          close_everything(req.client_fd, -1);
          fprintf(stderr, log_msg"client_fd: %d was closed because recv error\n", req.client_fd);
        } else if ((server->cqe->res == -ETIME || server->cqe->res == -ECANCELED) && req.state == TIMEOUT) {
          goto timeout;
        } else if (req.state == FIRST_READ) {
          close(req.client_fd);
        } else if (req.state == WRITE_ERR_TO_CLIENT) {
          close(req.client_fd);
          if (req.target_fd > 0) {
            close(req.target_fd);
          }
        }
        fprintf(stderr, log_msg"%s for event: %s\n", strerror(-server->cqe->res), state_to_str(req.state));
        fprintf(stderr, log_msg"-server->cqe->res=%d\n", -server->cqe->res);
        goto cq_advance;
      }

      switch (req.state) {
        case ACCEPT:
          req.client_fd = server->cqe->res;
          if (!(server->cqe->flags & IORING_CQE_F_MORE)) {
            add_accept_req(fd, accept_req, &server->ring);
            fprintf(stderr, log_msg"Some accept error\n");
          }
          if (setsockopt(req.client_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) < 0) {
            fprintf(stderr, log_msg"error req.client_fd: %d\n", req.client_fd);
            perror(log_msg"TCP_NODELAY");
            close(req.client_fd);
            break;
          }
          if (handler && func_call & ACCEPT) {
            log_req = from_client_t(req);
            handler(log_req, server);
          }
          client_req.val = 0;
          client_req.client_fd = req.client_fd;
          client_req.state = FIRST_READ;
          add_recv_req_with_timeout(req.client_fd, client_req, server->bgid, server->recv_timeout, &server->ring);
          break;
        case FIRST_READ:
          if (handler && func_call & FIRST_READ) {
            log_req = from_client_t(req);
            handler(log_req, server);
          }
          if (server->cqe->res <= 0) {
            close_everything(req.client_fd, -1);
            break;
          }
          client_req.val = 0;
          client_req.client_fd = req.client_fd;
          client_req.bid = server->cqe->flags >> IORING_CQE_BUFFER_SHIFT;
          if (handle_client_req(bufs[client_req.bid], server->cqe->res, &connects[req.client_fd]) == -1) {
            client_req.state = WRITE_ERR_TO_CLIENT;
            client_req.target_fd = -1;
            client_req.bid = server->cqe->flags >> IORING_CQE_BUFFER_SHIFT;
            add_send_req_with_timeout(req.client_fd, client_req, (char*)unsuccess_socks_ans, sizeof(unsuccess_socks_ans), server->send_timeout, &server->ring);
            fprintf(stderr, log_msg"handle_client_req == -1, server->cqe->flags >> IORING_CQE_BUFFER_SHIFT = %u\n", server->cqe->flags >> IORING_CQE_BUFFER_SHIFT);
            break;
          }
          int con_fd = socket(AF_INET, SOCK_STREAM, 0);
          // TODO: don't return
          if (con_fd == -1) bail(log_msg"client socket creation failed");
          if (setsockopt(con_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) < 0) close_bail(con_fd, log_msg"TCP_NODELAY");
          if (setsockopt(con_fd, IPPROTO_TCP, TCP_SYNCNT, (char *)&syn_retries, sizeof(syn_retries))) close_bail(con_fd, log_msg"TCP_SYNCNT");
          client_req.target_fd = con_fd;
          client_req.state = CONNECT;
          add_connect_req_with_timeout(client_req, &connects[client_req.client_fd], sizeof(struct sockaddr_in), server->connect_timeout, &server->ring);
          break;
        case CONNECT:
          if (handler && func_call & CONNECT) {
            log_req = from_client_t(req);
            handler(log_req, server);
          }
          client_req.val = 0;
          prep_sockets(req, client_req);
          client_req.state = WRITE_TO_CLIENT_AFTER_CONNECT;
          client_req.bid = req.bid;
          add_send_req_with_timeout(client_req.client_fd, client_req, (char*)success_socks_ans, sizeof(success_socks_ans), server->send_timeout, &server->ring);
          break;
        case WRITE_ERR_TO_CLIENT:
          fprintf(stderr, log_msg"WRITE_ERR_TO_CLIENT: uncorrect first socks4 send from client: %d\n", req.client_fd);
          if (handler && func_call & WRITE_ERR_TO_CLIENT) {
            log_req = from_client_t(req);
            handler(log_req, server);
          }
          shutdown(req.client_fd, SHUT_RDWR);
          close(req.client_fd);
          if (req.target_fd > 0) {
            close(req.target_fd);
          }
          add_provide_buf(server->br, bufs, req.bid);
          break;
        case WRITE_TO_CLIENT_AFTER_CONNECT:
          if (handler && func_call & WRITE_TO_CLIENT_AFTER_CONNECT) {
            log_req = from_client_t(req);
            handler(log_req, server);
          }
          add_provide_buf(server->br, bufs, req.bid);

          client_req.val = 0;
          prep_sockets(req, client_req);
          client_req.state = READ_FROM_CLIENT;
          add_recv_req_with_timeout(req.client_fd, client_req, server->bgid, server->recv_timeout, &server->ring);

          target_req.val = 0;
          prep_sockets(req, target_req);
          target_req.state = READ_FROM_CLIENT_PROXING;
          add_recv_req_with_timeout(req.target_fd, target_req, server->bgid, server->recv_timeout, &server->ring);
          break;
        case WRITE_TO_CLIENT:
          if (handler && func_call & WRITE_TO_CLIENT) {
            log_req = from_client_t(req);
            handler(log_req, server);
          }
          target_req.val = 0;
          prep_sockets(req, target_req);
          add_provide_buf(server->br, bufs, req.bid);
          target_req.state = READ_FROM_CLIENT_PROXING;
          add_recv_req_with_timeout(req.target_fd, target_req, server->bgid, server->recv_timeout, &server->ring);
          break;
        case READ_FROM_CLIENT:
          if (handler && func_call & READ_FROM_CLIENT) {
            log_req = from_client_t(req);
            handler(log_req, server);
          }
          if (server->cqe->res <= 0) {
            dbg(bufs[server->cqe->flags >> IORING_CQE_BUFFER_SHIFT][0] = 3);
            close_everything(-1, req.target_fd);
            break;
          }

          client_req.val = 0;
          prep_sockets(req, client_req);
          client_req.state = WRITE_TO_CLIENT_PROXING;
          client_req.bid = server->cqe->flags >> IORING_CQE_BUFFER_SHIFT;
          add_send_req_with_timeout(client_req.target_fd, client_req, bufs[client_req.bid], server->cqe->res, server->send_timeout, &server->ring);
          break;
        case WRITE_TO_CLIENT_PROXING:
          if (handler && func_call & WRITE_TO_CLIENT_PROXING) {
            log_req = from_client_t(req);
            handler(log_req, server);
          }
          client_req.val = 0;
          prep_sockets(req, client_req);
          add_provide_buf(server->br, bufs, req.bid);
          client_req.state = READ_FROM_CLIENT;
          add_recv_req_with_timeout(req.client_fd, client_req, server->bgid, server->recv_timeout, &server->ring);
          break;
        case READ_FROM_CLIENT_PROXING:
          if (handler && func_call & READ_FROM_CLIENT_PROXING) {
            log_req = from_client_t(req);
            handler(log_req, server);
          }
          if (server->cqe->res <= 0) {
            dbg(bufs[server->cqe->flags >> IORING_CQE_BUFFER_SHIFT][0] = 3);
            close_everything(req.client_fd, -1);
            break;
          }

          client_req.val = 0;
          prep_sockets(req, client_req);
          client_req.state = WRITE_TO_CLIENT;
          client_req.bid = server->cqe->flags >> IORING_CQE_BUFFER_SHIFT;
          add_send_req_with_timeout(req.client_fd, client_req, bufs[client_req.bid], server->cqe->res, server->send_timeout, &server->ring);
          break;
        case TIMEOUT:
          timeout:
            if (handler && func_call & TIMEOUT) {
              log_req = from_client_t(req);
              handler(log_req, server);
            }
            break;
      }
    }
    cq_advance:
      io_uring_cq_advance(&server->ring, count);
  }
  return 0;
}
