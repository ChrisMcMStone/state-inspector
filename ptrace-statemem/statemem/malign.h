#ifndef STATEMEM_MALIGN_H_
#define STATEMEM_MALIGN_H_

#include <stddef.h>

#include "statemem.h"
#include "trace.h"
#include "writebuffer.h"

typedef void dynalign_t;

extern dynalign_t *malign_init(logbuf_t *, const char *, const watchpoint_t *, const size_t, const size_t, const char *);
extern void malign_destroy(dynalign_t *);
extern void malign_process_malloc(dynalign_t *, trace_t *, uint64_t, uint64_t, uint64_t, watchpoint_t *);
extern void malign_process_free(dynalign_t *, trace_t *, uint64_t, uint64_t);

#endif
