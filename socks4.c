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

static const int yes = 1;
static const char success_socks_ans  [] = {0, 90, 0, 0, 0, 0, 0, 0};
static const char unsuccess_socks_ans[] = {0, 91, 0, 0, 0, 0, 0, 0};

const char *StateToStr[] = {
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
  "PROV_BUF"
};

static char bufs[BUFFERS_COUNT][MAX_MESSAGE_LEN] = {0};
static const int group_id = 0;

static inline void prep_sockets(client_t *old_req, client_t *new_req) {
  new_req->client_fd = old_req->client_fd;
  new_req->client_proxing_fd = old_req->client_proxing_fd;
}

int setup_listening_socket(struct socks4_server* server) {
  int fd = server->server_fd;
  struct io_uring_params params = {0};
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) < 0) close_bail(fd, log_msg"SO_REUSEADDR");
  if (bind(fd, (struct sockaddr *)&server->server_addr, sizeof(server->server_addr)) == -1) close_bail(fd, log_msg"bind");
  if (listen(fd, 512) == -1) close_bail(fd, log_msg"listen");
  params.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_CLAMP;
	//params.flags |= IORING_SETUP_CQSIZE;
	params.flags |= IORING_SETUP_COOP_TASKRUN;
	params.flags |= IORING_SETUP_DEFER_TASKRUN;
  int rv = io_uring_queue_init_params(QUEUE_DEPTH, &server->ring, &params);
  if (rv) {
    fprintf(stderr, "io_uring_queue_init_params: %s\n", strerror(-rv));
    close(fd);
    return -1;
  }
  dbg(printf(log_msg"sq ring entries: %u\n", server->ring.sq.ring_entries));
  dbg(printf(log_msg"cq ring entries: %u\n", server->ring.cq.ring_entries));
  dbg(printf(log_msg"ring features: %u\n", server->ring.features));
  struct io_uring_sqe *sqe = io_uring_get_sqe(&server->ring);
  io_uring_prep_provide_buffers(sqe, bufs, MAX_MESSAGE_LEN, BUFFERS_COUNT, group_id, 0);
  io_uring_submit(&server->ring);
  io_uring_wait_cqe(&server->ring, &server->cqe);
  if (server->cqe->res < 0) {
    fprintf(stderr, "cqe->res = %d\n", server->cqe->res);
    return -1;
  }
  io_uring_cqe_seen(&server->ring, server->cqe);
  return 0;
}

int handle_client_req(char *buf, size_t buf_len, struct sockaddr_in *sin) {
  if (buf_len < 3 || buf_len > 30) {
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

int handle_cons(struct socks4_server* server) {
  int fd = server->server_fd;
  client_t *req, *client_req, *dst_host;
  socklen_t client_addr_len = sizeof(struct sockaddr_in);
  add_accept_req(fd, &client_addr_len, &server->ring);
  for (;;) {
    int ret = io_uring_wait_cqe(&server->ring, &server->cqe);
    //int ret = io_uring_wait_cqe_timeout(&server->ring, &server->cqe, server->ts);
    if (ret < 0) bail(log_msg"io_uring_wait_cqe");
    req = (client_t*)server->cqe->user_data;
    if (server->cqe->res < 0) {
      // TODO: if for state we have fds - maybe close them. And if we have bids maybe call add_provide_buf
      fprintf(stderr, log_msg"%s for event: %s\n", strerror(-server->cqe->res), StateToStr[req->state]);
      fprintf(stderr, log_msg"-server->cqe->res=%d\n", -server->cqe->res);
      // close(req->client_fd);
      // close(req->client_proxing_fd);
      free(req);
      io_uring_cqe_seen(&server->ring, server->cqe);
      continue;
    }

    switch (req->state) {
      case ACCEPT:
        req->client_fd = server->cqe->res;

#ifdef SOCKS_DEBUG
        char client_ip_str[INET_ADDRSTRLEN];
        struct sockaddr_in *client_addr = (struct sockaddr_in*)req->send_buf;
        inet_ntop(AF_INET, &client_addr->sin_addr, client_ip_str, INET_ADDRSTRLEN);
        printf(log_msg"Accepted connection from: %s:%u\n", client_ip_str, client_addr->sin_port);
#endif

        free(req->send_buf);
        if (setsockopt(req->client_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) < 0) {
          fprintf(stderr, log_msg"error req->client_fd: %d\n", req->client_fd);
          perror(log_msg"TCP_NODELAY");
          close(req->client_fd);
          add_accept_req(fd, &client_addr_len, &server->ring);
          free(req);
          break;
        }
        client_req = (client_t*)malloc(sizeof(client_t));
        client_req->client_fd = req->client_fd;
        client_req->state = FIRST_READ;
        add_recv_req(req->client_fd, client_req, &server->ring);
        dbg(printf(log_msg"accept fd: %d\n", req->client_fd));
        free(req);
        add_accept_req(fd, &client_addr_len, &server->ring);
        break;
      case FIRST_READ:
        if (!server->cqe->res) {
          close(req->client_fd);
          dbg(printf("\n"log_msg"server->cqe->res=0, closed client_fd: %d\n", req->client_fd));
          free(req);
          break;
        }
        dbg(printf("\n"log_msg"first read from client: %d\n", req->client_fd));
        client_req = (client_t*)malloc(sizeof(client_t));
        client_req->client_fd = req->client_fd;
        client_req->client_bid = server->cqe->flags >> 16;
        struct sockaddr_in *proxy_client_dst = malloc(client_addr_len);

        if (handle_client_req(bufs[server->cqe->flags >> 16], server->cqe->res, proxy_client_dst) == -1) {
          client_req->state = WRITE_ERR_TO_CLIENT;
          client_req->send_buf = (char*)unsuccess_socks_ans;
          client_req->send_len = sizeof(unsuccess_socks_ans);
          add_send_req(req->client_fd, client_req, &server->ring);
          // add_provide_buf(&server->ring, bufs, server->cqe->flags >> 16, group_id);
          fprintf(stderr, log_msg"handle_client_req == -1, server->cqe->flags >> 16 = %u\n", server->cqe->flags >> 16);
          free(req);
          free(proxy_client_dst);
          break;
        }
        client_req->send_buf = (char*)proxy_client_dst; // TODO: maybe add new field
        dbg(printf(log_msg"server->cqe->flags >> 16 = %u\n", server->cqe->flags >> 16));
        //add_provide_buf(&server->ring, bufs, server->cqe->flags >> 16, group_id);
#ifdef SOCKS_DEBUG
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &proxy_client_dst->sin_addr, dst_ip_str, INET_ADDRSTRLEN);
        printf(log_msg"Connect to dst: %s:%u\n", dst_ip_str, proxy_client_dst->sin_port);
#endif
        int con_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (con_fd == -1) bail("client socket creation failed");
        if (setsockopt(con_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(int)) < 0) close_bail(con_fd, log_msg"TCP_NODELAY");
        dbg(printf(log_msg"client_proxing_fd: %d\n", con_fd));
        client_req->client_proxing_fd = con_fd;
        client_req->state = CONNECT;
        add_connect_req(client_req, proxy_client_dst, sizeof(*proxy_client_dst), &server->ring);
        //add_provide_buf(&server->ring, bufs, server->cqe->flags >> 16, group_id);
        free(req);
        break;
      case CONNECT:
        client_req = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, client_req);
        client_req->send_buf = (char*)success_socks_ans;
        client_req->send_len = sizeof(success_socks_ans);
        client_req->state = WRITE_TO_CLIENT_AFTER_CONNECT;
        client_req->client_bid = req->client_bid;
        add_send_req(client_req->client_fd, client_req, &server->ring);
        dbg(printf(log_msg"Connect req, client_fd: %d, client_proxing_fd: %d\n", req->client_fd, req->client_proxing_fd));
        //add_provide_buf(&server->ring, bufs, req->client_bid, group_id);
        free(req->send_buf);
        free(req);
        break;
      case WRITE_ERR_TO_CLIENT:
        fprintf(stderr, log_msg"WRITE_ERR_TO_CLIENT: uncorrect first socks4 send from client: %d\n", req->client_fd);
        shutdown(req->client_fd, SHUT_RDWR);
        close(req->client_fd);
        add_provide_buf(&server->ring, bufs, req->client_bid, group_id);
        free(req);
        break;
      case WRITE_TO_CLIENT_AFTER_CONNECT:
        //bid = server->cqe->flags >> 16;
        //add_provide_buf(&server->ring, bufs, __u16 bid, unsigned int gid)
        add_provide_buf(&server->ring, bufs, req->client_bid, group_id);
        client_req = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, client_req);
        client_req->state = READ_FROM_CLIENT;
        add_recv_req(req->client_fd, client_req, &server->ring);

        dst_host = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, dst_host);
        dst_host->state = READ_FROM_CLIENT_PROXING;
        add_recv_req(req->client_proxing_fd, dst_host, &server->ring);

        dbg(printf(log_msg"WRITE_TO_CLIENT_AFTER_CONNECT, client_fd: %d, client_proxing_fd: %d\n", req->client_fd, req->client_proxing_fd));
        free(req);
        break;
      case WRITE_TO_CLIENT:
        //add_provide_buf(&server->ring, bufs, server->cqe->flags >> 16, group_id);
        dst_host = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, dst_host);
        add_provide_buf(&server->ring, bufs, req->client_proxing_bid, group_id);
        dst_host->state = READ_FROM_CLIENT_PROXING;
        //dst_host->client_proxing_bid = req->client_proxing_bid;
        add_recv_req(req->client_proxing_fd, dst_host, &server->ring);
        dbg(printf(log_msg"WRITE_TO_CLIENT, client_fd: %d, client_proxing_fd: %d\n", req->client_fd, req->client_proxing_fd));

        free(req);
        break;
      case READ_FROM_CLIENT:
        dbg(printf(log_msg"READ_FROM_CLIENT: %d, %d bytes\n", req->client_fd, server->cqe->res));
        // dbg(printf("server->cqe->flags >> 16: %d, req->client_bid: %d, req->client_proxing_bid: %d\n",
        //   server->cqe->flags >> 16, req->client_bid, req->client_proxing_bid
        // ));
        if (server->cqe->res <= 0) {
          dbg(bufs[server->cqe->flags >> 16][0] = 3);
          //add_provide_buf(&server->ring, bufs, server->cqe->flags >> 16, group_id);
          shutdown(req->client_proxing_fd, SHUT_RDWR);
          // shutdown(req->client_fd, SHUT_RDWR);
          close(req->client_proxing_fd);
          //close(req->client_fd);

          dbg(printf(log_msg"exit=0, closed client_proxing_fd: %d, add_provide_buf: %u\n", req->client_proxing_fd, server->cqe->flags >> 16));
          free(req);
          break;
        }

        client_req = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, client_req);
        client_req->state = WRITE_TO_CLIENT_PROXING;
        client_req->send_buf = bufs[server->cqe->flags >> 16];
        client_req->send_len = server->cqe->res;
        client_req->client_bid = server->cqe->flags >> 16;
        add_send_req(client_req->client_proxing_fd, client_req, &server->ring);
        free(req);
        break;
      case WRITE_TO_CLIENT_PROXING:
        //add_provide_buf(&server->ring, bufs, server->cqe->flags >> 16, group_id);
        client_req = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, client_req);
        add_provide_buf(&server->ring, bufs, req->client_bid, group_id);
        client_req->state = READ_FROM_CLIENT;
        //client_req->client_bid = req->client_bid;
        add_recv_req(req->client_fd, client_req, &server->ring);
        dbg(printf(log_msg"WRITE_TO_CLIENT_PROXING, client_fd: %d, client_proxing_fd: %d\n", req->client_fd, req->client_proxing_fd));

        free(req);
        break;
      case READ_FROM_CLIENT_PROXING:
        dbg(printf(log_msg"READ_FROM_CLIENT_PROXING: %d, %d bytes\n", req->client_proxing_fd, server->cqe->res));
        // dbg(printf("server->cqe->flags >> 16: %d, req->client_bid: %d, req->client_proxing_bid: %d\n",
        //   server->cqe->flags >> 16, req->client_bid, req->client_proxing_bid
        // ));
        if (server->cqe->res <= 0) {
          //shutdown(req->client_proxing_fd, SHUT_RDWR);
          dbg(bufs[server->cqe->flags >> 16][0] = 3);
          //add_provide_buf(&server->ring, bufs, server->cqe->flags >> 16, group_id);

          shutdown(req->client_fd, SHUT_RDWR);
          //close(req->client_proxing_fd);
          close(req->client_fd);
          dbg(printf(log_msg"exit=0, closed client_fd: %d, add_provide_buf: %u\n", req->client_fd, server->cqe->flags >> 16));
          free(req);
          break;
        }

        client_req = (client_t*)malloc(sizeof(client_t));
        prep_sockets(req, client_req);
        client_req->send_buf = bufs[server->cqe->flags >> 16];
        client_req->send_len = server->cqe->res;
        client_req->state = WRITE_TO_CLIENT;
        client_req->client_proxing_bid = server->cqe->flags >> 16;
        add_send_req(req->client_fd, client_req, &server->ring);
        free(req);
        break;
      case PROV_BUF:
        dbg(memset(bufs[req->client_bid], 2, sizeof(bufs[req->client_bid])));
        dbg(printf(log_msg"PROV_BUF bid: %u\n", req->client_bid));
        free(req);
        break;
    }
    io_uring_cqe_seen(&server->ring, server->cqe);
  }
  return 0;
}
