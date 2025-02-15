#ifndef SOCKS4_H
#define SOCKS4_H

#include <sys/time.h>
#include <netinet/in.h>
#include <liburing.h>

#define SOCKS4_VER 4
#define SOCKS4_CONNECT_COMMAD 1
#define SOCKS4_BIND_COMMAND 2
#define QUEUE_DEPTH 256
#define BUF_SIZE 4096

#define ANTOHS(data, i) \
  (((uint16_t)data[i] << 8) + (uint8_t)data[i + 1])

typedef enum {
  recv_cons,
  con_to_dst,
  sending_error,
  proxing
} server_state;

typedef enum {
  ACCEPT,
  READ_FROM_CLIENT,
  READ_FROM_CLIENT_PROXING,
  FIRST_READ,
  WRITE_TO_CLIENT,
  WRITE_TO_CLIENT_AFTER_CONNECT,
  WRITE_TO_CLIENT_PROXING,
  CONNECT
} event_type;

struct socks4_server {
  int server_fd;
  server_state state;
  struct sockaddr_in server_addr;
  struct timeval* con_timeout;
  struct timeval* recv_timeout;
  struct timeval* send_timeout;
  struct io_uring ring;
  struct io_uring_cqe *cqe;
};

typedef struct {
  int client_fd;
  int client_proxing_fd;
  event_type state;
  char* recv_buf;
  size_t recv_len;
  char* send_buf;
  size_t send_buf_len;
} client_t;

int setup_listening_socket(struct socks4_server* server);
int handle_cons(struct socks4_server* server);
// int connect_to_dst(struct socks4_server* server, client_t* req, struct sockaddr_in* client_dst);

#endif
