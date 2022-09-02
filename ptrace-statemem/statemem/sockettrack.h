#ifndef STATEMEM_SOCKETTRACK_H_
#define STATEMEM_SOCKETTRACK_H_

#include <stddef.h>
#include <sys/types.h>

typedef void socket_map_t;

extern socket_map_t *socketmap_init(void);
extern void socketmap_destroy(socket_map_t *t);

extern void socketmap_add(socket_map_t *t, pid_t pid, int fd);
extern bool socketmap_exists(socket_map_t *t, pid_t pid, int fd);

#endif

