#ifndef SOCKS4_H
#define SOCKS4_H

#include <netinet/in.h>
#include <liburing.h>
#include <stdio.h>


#define SOCKS4_VER            4
#define SOCKS4_CONNECT_COMMAD 1
#define SOCKS4_BIND_COMMAND   2
#define MIN_SOCKS_CONNECT_LEN 8
#define MAX_SOCKS_CONNECT_LEN 30

// TODO: don't hardcode it
#define QUEUE_DEPTH     2048
#define MAX_MESSAGE_LEN 4096
#define BUFFERS_COUNT   2048


#define ANTOHS(data, i) \
  (((uint16_t)(data)[(i)] << 8) + (uint8_t)(data)[(i) + 1])

typedef enum {
  ACCEPT=                        1<<0,
  READ_FROM_CLIENT=              1<<1,
  READ_FROM_CLIENT_PROXING=      1<<2,
  FIRST_READ=                    1<<3,
  WRITE_ERR_TO_CLIENT=           1<<4,
  WRITE_TO_CLIENT=               1<<5,
  WRITE_TO_CLIENT_AFTER_CONNECT= 1<<6,
  WRITE_TO_CLIENT_PROXING=       1<<7,
  CONNECT=                       1<<8,
  TIMEOUT=                       1<<9,
} event_type;

#define ALL_EVENT_TYPES \
  ACCEPT| \
  READ_FROM_CLIENT| \
  READ_FROM_CLIENT_PROXING| \
  FIRST_READ| \
  WRITE_ERR_TO_CLIENT| \
  WRITE_TO_CLIENT| \
  WRITE_TO_CLIENT_AFTER_CONNECT| \
  WRITE_TO_CLIENT_PROXING| \
  CONNECT|\
  TIMEOUT\

struct socks4_server {
  int server_fd;
  struct sockaddr_in server_addr;
  struct __kernel_timespec *recv_timeout;
  struct io_uring ring;
  struct io_uring_buf_ring *br;
  struct io_uring_cqe *cqe;
  unsigned short bgid;
};

typedef struct {
  int client_fd;
  int target_fd;
  event_type state;
  char *send_buf;
  size_t send_len;
  __u16 client_bid;
  __u16 target_bid;
} client_t;

int setup_listening_socket(struct socks4_server *server);

int socks4_setup_io_uring_queue(struct socks4_server* server);

int handle_cons(struct socks4_server* server, void (*handler)(client_t*, struct socks4_server*), event_type func_call);

#endif
