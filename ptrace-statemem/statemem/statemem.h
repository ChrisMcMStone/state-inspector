#ifndef STATEMEM_H_
#define STATEMEM_H_

#include <stdint.h>
#include <unistd.h>

enum malloc_bp_id {
  MALLOC_CALL,
  CALLOC_CALL,
  FREE_CALL,
  XALLOC_RET,
  MALLOC_BP_END
};

typedef struct watchpoint {
  uint64_t base_address;
  size_t alloc_size;
  intptr_t address;
  intptr_t aligned_address;
  size_t size;
} watchpoint_t;

int read_memory(pid_t pid, void *out, size_t len, off_t address);

#endif
