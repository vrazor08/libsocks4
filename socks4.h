#ifndef SOCKS4_H
#define SOCKS4_H

#include <sys/time.h>
#include <netinet/in.h>
#include <liburing.h>
#include <stdio.h>

#define SOCKS4_VER 4u
#define SOCKS4_CONNECT_COMMAD 1
#define SOCKS4_BIND_COMMAND 2
#define QUEUE_DEPTH 2048

#define MAX_MESSAGE_LEN 4096
#define BUFFERS_COUNT   2048

#define ANTOHS(data, i) \
  (((uint16_t)(data)[(i)] << 8) + (uint8_t)(data)[(i) + 1])

typedef enum {
  ACCEPT=1,
  READ_FROM_CLIENT,
  READ_FROM_CLIENT_PROXING,
  FIRST_READ,
  WRITE_ERR_TO_CLIENT,
  WRITE_TO_CLIENT,
  WRITE_TO_CLIENT_AFTER_CONNECT,
  WRITE_TO_CLIENT_PROXING,
  CONNECT,
  PROV_BUF
} event_type;

struct socks4_server {
  int server_fd;
  struct sockaddr_in server_addr;
  struct __kernel_timespec *ts;
  struct io_uring ring;
  struct io_uring_cqe *cqe;
};

typedef struct {
  int client_fd;
  int client_proxing_fd;
  event_type state;
  char *send_buf;
  size_t send_len;
  __u16 client_bid;
  __u16 client_proxing_bid;
} client_t;

int setup_listening_socket(struct socks4_server *server);
int handle_cons(struct socks4_server *server);

#endif
