#ifndef ERR_H
#define ERR_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define log_msg "[" __FILE__ ":" TOSTRING(__LINE__) "] "

#define bail(msg) do { \
  perror(msg); \
  return -1; \
  } while(0);
#define close_bail(fd, msg) do { \
  close((fd)); \
  bail(msg) \
  } while(0);
#endif
