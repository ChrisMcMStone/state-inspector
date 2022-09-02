#include <asm/unistd_64.h>
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <errno.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>

#include "logger.h"

// ptrace-burrito
#include "breakpoints.h"
#include "debug.h"
#include "debug_syscalls.h"
#include "errors.h"
#include "process.h"
#include "symbols.h"
#include "trace.h"
#include "util.h"

#include "malign.h"
#include "netlink.h"
#include "writebuffer.h"
#include "statemem.h"
#include "resolve.h"

#define MAPS_LINE_MAX (PATH_MAX * 2)

typedef struct map_range {
  unsigned long long low, high;
} map_range_t;

static pid_t trace_malloc_pid_next = -1;

static int session_id = 0;
const char *app = NULL;
const char *dump_dir = NULL;
//static int mgmt_recv_count = 0;
//static int mgmt_send_count = 0;
//static int eapol_send_count = 0;
//static int eapol_recv_count = 0;
static ssize_t cached_fd = -1;

static watchpoint_t watchpoints[MAX_BREAKPOINTS];
static size_t watchpoint_count = 0;
static unsigned long long watchpoint_hits = 0;
static long wdnum_min = -1;
static long wdnum_max = -1;
static long dnum = 0;

static char logger_path[PATH_MAX] = {0};
static stringbuf_t *logger = NULL;
static char mallocs_path[PATH_MAX] = {0};
static stringbuf_t *mallocs = NULL;
static bool opt_zero_mem = false;
static bool opt_ff_mem = false;
static dynalign_t *dynalign;

static logbuf_t *logbuf = NULL;
static int signal_attach = 0;

static inline void fatal(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);

  fputc('\n', stderr);
  exit(EXIT_FAILURE);
}

static void write_mem_maps(pid_t pid, char *outfile) {
  char path[PATH_MAX];
  unsigned char buf[PATH_MAX * 2];
  size_t len = 0;

  snprintf(path, sizeof(path), "/proc/%u/maps", pid);

  FILE *fd = fopen(path, "r");
  if (!fd) {
    fatal("cannot open /proc/%u/maps", pid);
  }

  wb_reinit(logbuf, outfile);

  do {
    if ((len = fread(buf, 1, sizeof(buf), fd)) > 0) {
      wb_add_bytes(logbuf, outfile, buf, len);
    }
  } while (len);

  fclose(fd);
}

static inline int get_maps(pid_t pid, const char *name, map_range_t *range) {
  char path[PATH_MAX], *line = NULL;
  size_t line_max = 0;
  bool main_bin = false;
  bool multi_range_start = false;

  snprintf(path, sizeof(path), "/proc/%u/maps", pid);

  FILE *fd = fopen(path, "r");
  if (!fd) {
    fatal("cannot open /proc/%u/maps", pid);
  }

  if (strcmp(name, app) == 0)
    main_bin = true;

  while (getline(&line, &line_max, fd) > 0) {
    if (strstr(line, name)) {
      char *highp = line;
      while (*highp++ != '-')
        ;
      if (!*highp)
        fatal("range separator not found in /proc/%u/maps", pid);
      range->high = strtoull(highp, NULL, 16);
      if (!multi_range_start) {
        range->low = strtoull(line, NULL, 16);
        multi_range_start = true;
      }
      if (!main_bin) {
        free(line);
        fclose(fd);
        return 0;
      }
    }
  }
  if (line)
    free(line);
  fclose(fd);
  // High range was found, so return 0
  if (range->high)
    return 0;
  return -1;
}

static inline int get_heap_maps(pid_t pid, map_range_t *range) {
  return get_maps(pid, "[heap]", range);
}

static inline int get_stack_maps(pid_t pid, map_range_t *range) {
  return get_maps(pid, "[stack]", range);
}

static inline int get_binary_maps(pid_t pid, map_range_t *range) {
  return get_maps(pid, app, range);
}

static inline void dump_memory(pid_t pid, const char *file,
                               map_range_t *range) {
  char path[PATH_MAX] = {0};
  unsigned char buf[BUFSIZ] = {0};

  snprintf(path, sizeof(path), "/proc/%u/mem", pid);

  FILE *fdi = fopen(path, "rb");
  if (!fdi)
    fatal("cannot open /proc/%u/mem", pid);

  unsigned long long size = range->high - range->low;
  fseeko(fdi, range->low, SEEK_SET);

  wb_reinit(logbuf, file);

  while (size > 0) {
    size_t nb = fread(buf, 1, (sizeof(buf) > size) ? size : sizeof(buf), fdi);
    if (nb == 0)
      fatal("error dumping process memory: %llx - %llx", range->low,
            range->high);
    wb_add_bytes(logbuf, file, buf, nb);
    size -= nb;
  }

  fclose(fdi);

  return;
}

static inline void dump_registers(trace_t *t, stringbuf_t *file) {
  get_registers(t);

  strb_puts(file, "{\n");
  strb_printf(file, "    \"r15\": %llu,\n", t->regs.r15);
  strb_printf(file, "    \"r14\": %llu,\n", t->regs.r14);
  strb_printf(file, "    \"r13\": %llu,\n", t->regs.r13);
  strb_printf(file, "    \"r12\": %llu,\n", t->regs.r12);
  strb_printf(file, "    \"rbp\": %llu,\n", t->regs.rbp);
  strb_printf(file, "    \"rbx\": %llu,\n", t->regs.rbx);
  strb_printf(file, "    \"r11\": %llu,\n", t->regs.r11);
  strb_printf(file, "    \"r10\": %llu,\n", t->regs.r10);
  strb_printf(file, "    \"r9\": %llu,\n", t->regs.r9);
  strb_printf(file, "    \"r8\": %llu,\n", t->regs.r8);
  strb_printf(file, "    \"rax\": %llu,\n", t->regs.rax);
  strb_printf(file, "    \"rcx\": %llu,\n", t->regs.rcx);
  strb_printf(file, "    \"rdx\": %llu,\n", t->regs.rdx);
  strb_printf(file, "    \"rsi\": %llu,\n", t->regs.rsi);
  strb_printf(file, "    \"rdi\": %llu,\n", t->regs.rdi);
  strb_printf(file, "    \"orig_rax\": %llu,\n", t->regs.orig_rax);
  strb_printf(file, "    \"rip\": %llu,\n", t->regs.rip);
  strb_printf(file, "    \"cs\": %llu,\n", t->regs.cs);
  strb_printf(file, "    \"eflags\": %llu,\n", t->regs.eflags);
  strb_printf(file, "    \"rsp\": %llu,\n", t->regs.rsp);
  strb_printf(file, "    \"ss\": %llu,\n", t->regs.ss);
  strb_printf(file, "    \"fs_base\": %llu,\n", t->regs.fs_base);
  strb_printf(file, "    \"gs_base\": %llu,\n", t->regs.gs_base);
  strb_printf(file, "    \"ds\": %llu,\n", t->regs.ds);
  strb_printf(file, "    \"es\": %llu,\n", t->regs.es);
  strb_printf(file, "    \"fs\": %llu,\n", t->regs.fs);
  strb_printf(file, "    \"gs\": %llu\n", t->regs.gs);
  strb_puts(file, "  },\n");
}

static void trace_malloc_init(trace_t *t, trace_t *parent, void *data) {
  if (parent == NULL) {
#if 1
    uintptr_t offset = 0;
    const char *lib_name = get_symbol("malloc", &offset);

    add_breakpoint_fileoff(t, MALLOC_CALL, lib_name, offset,
                           BP_COPY_EXEC | BP_COPY_CHILD);

    lib_name = get_symbol("calloc", &offset);

    add_breakpoint_fileoff(t, CALLOC_CALL, lib_name, offset,
                           BP_COPY_EXEC | BP_COPY_CHILD);

    lib_name = get_symbol("free", &offset);
    add_breakpoint_fileoff(t, FREE_CALL, lib_name, offset,
                           BP_COPY_EXEC | BP_COPY_CHILD);
#else
    add_breakpoint_address(t, MALLOC_CALL, resolve_libc_function(t->pid, "malloc"), BP_COPY_EXEC | BP_COPY_CHILD);
    add_breakpoint_address(t, CALLOC_CALL, resolve_libc_function(t->pid, "calloc"), BP_COPY_EXEC | BP_COPY_CHILD);
    add_breakpoint_address(t, FREE_CALL, resolve_libc_function(t->pid, "free"), BP_COPY_EXEC | BP_COPY_CHILD);
#endif
    if (signal_attach) {
      kill(t->pid, SIGUSR1);
    }
  }
}

static void trace_malloc_enable_trace(trace_t *t) {
  trace_syscalls(t, 0);
  disable_breakpoint(t, MALLOC_CALL);
  disable_breakpoint(t, CALLOC_CALL);
  disable_breakpoint(t, FREE_CALL);
  for (int i = MALLOC_BP_END; i < MALLOC_BP_END + watchpoint_count; i++) {
    disable_breakpoint(t, i);
  }

  add_watchpoint_address(t, XALLOC_RET, get_sp(t), PROT_READ | PROT_WRITE,
                         sizeof(uintptr_t), BP_COPY_CHILD);
}

static void trace_malloc_disable_trace(trace_t *t) {
  del_breakpoint(t, XALLOC_RET);
  enable_breakpoint(t, MALLOC_CALL);
  enable_breakpoint(t, CALLOC_CALL);
  enable_breakpoint(t, FREE_CALL);

  for (int i = MALLOC_BP_END; i < MALLOC_BP_END + watchpoint_count; i++) {
    enable_breakpoint(t, i);
  }
  trace_syscalls(t, 1);
}

// static void trace_malloc_post_call(trace_t *t, void *data)
//{
//  (*(void (*)(trace_t *, void *))data)(t, NULL);
//}

static void trace_malloc_exec(trace_t *t, void *data) {
  // trace_syscalls(t, 1);
}

static pid_t trace_malloc_pid(void *data) { return trace_malloc_pid_next; }

static void trace_malloc_hit(trace_t *t, void *data) {
  static size_t last_malloc_sz = 0;
  switch (current_breakpoint_id(t)) {
  case MALLOC_CALL: {
    int64_t monotone = logger_get_monotone();
    strb_printf(mallocs, "%" PRIi64 " M %#lx %#lx ", monotone, get_sp(t),
                get_func_arg(t, 0));
    trace_malloc_pid_next = t->pid;
    trace_malloc_enable_trace(t);
    last_malloc_sz = get_func_arg(t, 0);
    break;
  }
  case CALLOC_CALL: {
    int64_t monotone = logger_get_monotone();
    strb_printf(mallocs, "%" PRIi64 " M %#lx %#lx ", monotone, get_sp(t),
                get_func_arg(t, 0) * get_func_arg(t, 1));
    trace_malloc_pid_next = t->pid;
    trace_malloc_enable_trace(t);
    break;
  }
  case XALLOC_RET:
    strb_printf(mallocs, "%#lx\n", get_func_result(t));

    if (opt_zero_mem && last_malloc_sz && get_func_result(t)) {
      if ((get_func_result(t) & 0x7f0000000000) != 0x7f0000000000) {
        memzero(t->pid, (void *)get_func_result(t), last_malloc_sz);
      }
    } else if (opt_ff_mem && last_malloc_sz && get_func_result(t)) {
      memff(t->pid, (void *)get_func_result(t), last_malloc_sz);
    }

    trace_malloc_pid_next = -1;
    trace_malloc_disable_trace(t);
    last_malloc_sz = 0;
    break;
  case FREE_CALL: {
    int64_t monotone = logger_get_monotone();
    strb_printf(mallocs, "%" PRIi64 " F %#lx %#lx\n", monotone, get_sp(t),
                get_func_arg(t, 0));
    break;
  }
  default:
    break;
  }
}

static void trace_malloc_detach(trace_t *t, void *data) {
  if (trace_malloc_pid_next == t->pid) {
    trace_malloc_pid_next = -1;
  }
}

int read_memory(pid_t pid, void *out, size_t len, off_t address) {
  char file[64];
  int fd;

  sprintf(file, "/proc/%ld/mem", (long)pid);
  fd = open(file, O_RDONLY);
  if (fd <= 0) {
    perror("failed to open child memory");
    return -1;
  }

  ssize_t rval = pread(fd, out, len, address);
  if (rval == -1) {
    fprintf(stderr, "failed to read child memory at 0x%08lX: ", address);
    perror("");
    return -1;
  } else if (rval != len) {
    perror("could not readl all requested memory from child");
    return -1;
  }

  close(fd);
  return 0;
}

static void watchpoints_hit(trace_t *t, void *data) {
  // this will likely bite us later....
  static long alloc_sp = -1, alloc_arg = -1;
  static size_t last_malloc_sz = 0;

  switch (current_breakpoint_id(t)) {
  case MALLOC_CALL: {
    alloc_sp = get_sp(t);
    alloc_arg = get_func_arg(t, 0);

    trace_malloc_pid_next = t->pid;
    trace_malloc_enable_trace(t);

    last_malloc_sz = get_func_arg(t, 0);
    break;
  }
  case CALLOC_CALL: {
    alloc_sp = get_sp(t);
    alloc_arg = get_func_arg(t, 0) * get_func_arg(t, 1);

    trace_malloc_pid_next = t->pid;
    trace_malloc_enable_trace(t);
    break;
  }
  case XALLOC_RET:
    trace_malloc_pid_next = -1;
    trace_malloc_disable_trace(t);

    if (opt_zero_mem && last_malloc_sz && get_func_result(t)) {
      if ((get_func_result(t) & 0x7f0000000000) != 0x7f0000000000) {
        memzero(t->pid, (void *)get_func_result(t), last_malloc_sz);
      }
    }

    malign_process_malloc(dynalign, t, alloc_sp, alloc_arg, get_func_result(t),
                          (watchpoint_t *)watchpoints);
    alloc_sp = -1;
    alloc_arg = -1;

    last_malloc_sz = 0;
    break;
  case FREE_CALL: {
    malign_process_free(dynalign, t, get_sp(t), get_func_arg(t, 0));
    break;
  }
  default: {
    if (wdnum_min >=0 && dnum <= wdnum_min ) return;
    if (wdnum_max >=0 && dnum >= wdnum_max ) return;

    int id = current_breakpoint_id(t);
    if (id >= MALLOC_BP_END && id < watchpoint_count + MALLOC_BP_END) {
      id -= MALLOC_BP_END;
      map_range_t bin_range = {0};
      get_binary_maps(t->pid, &bin_range);

      unsigned long pc = get_pc(t);
      if (!(pc >= bin_range.low && pc < bin_range.high))
        return;

      char prefix[128] = {0};
      snprintf(prefix, sizeof(prefix), "sessID-%d-watchpoint-%llu", session_id,
               ++watchpoint_hits);
      char log_fname[PATH_MAX] = {0};
      char fname[PATH_MAX] = {0};
      map_range_t range = {0};

      int64_t monotone = logger_get_monotone();

      // dump meta
      snprintf(log_fname, sizeof(fname), "%s/%s.log", dump_dir, prefix);
      stringbuf_t *log = strb_init();
      if (!log) {
        fatal("cannot create log buffer for %s", fname);
      }

      strb_puts(log, "{\n");

      strb_printf(log, "  \"timestamp\": %" PRIi64 ",\n", monotone);
      strb_printf(log, "  \"malloc_log\": \"%s/malloc%d.log\",\n", dump_dir,
                  session_id);

      strb_printf(log,
                  "  \"address\": %llu,\n  \"orig_address\": %llu,\n"
                  "  \"size\": %d,\n  \"registers\": ",
                  (unsigned long long)watchpoints[id].aligned_address,
                  (unsigned long long)watchpoints[id].address,
                  watchpoints[id].size);
      dump_registers(t, log);

      strb_printf(log, "  \"pc\": %lu,\n", pc);

      snprintf(fname, sizeof(fname), "%s/%s_stack.dump", dump_dir, prefix);
      get_stack_maps(t->pid, &range);

      strb_printf(log, "  \"stack_base\": %llu,\n", range.low);
      dump_memory(t->pid, fname, &range);

      snprintf(fname, sizeof(fname), "%s/%s_heap.dump", dump_dir, prefix);
      get_heap_maps(t->pid, &range);
      strb_printf(log, "  \"heap_base\": %llu,\n", range.low);
      dump_memory(t->pid, fname, &range);

      size_t size = watchpoints[id].size;
      unsigned char *wp_value = (unsigned
char*)malloc(watchpoints[id].size*sizeof(unsigned char)); read_memory(t->pid,
wp_value, sizeof(wp_value), watchpoints[id].aligned_address); char *b64_val =
base64_encode(wp_value, size, &size); b64_val[size]=0;

      strb_puts(log, "  \"wp_value\": \"");
      strb_printf(log, "%s", b64_val);
      strb_puts(log, "\",\n");

      free(wp_value);

      // dump loaded segments

      char *line = NULL;
      size_t line_max = 0, segment_count = 0;
      snprintf(fname, sizeof(fname), "/proc/%u/maps", t->pid);

      FILE *fd = fopen(fname, "r");
      if (!fd) {
        fatal("cannot open /proc/%u/maps", t->pid);
      }

      const char *exe = get_proc_exe(t->pid);
      if (!exe) {
        fatal("cannot get executable for pid; cannot dump segments");
      }

      strb_puts(log, "  \"segments\": [\n");

      bool is_gnutls = strcmp(app, "gnutls") == 0;

      size_t segments = 0;
      while (getline(&line, &line_max, fd) > 0) {
        if (strstr(line, exe) || (is_gnutls && strstr(line, "libgnutls.so"))) {
          if (segments++ > 0) {
            strb_puts(log, ",\n");
          }

          char *highp = line;
          while (*highp && *highp++ != '-')
            ;
          if (!*highp)
            fatal("range separator not found in /proc/%u/maps", t->pid);

          char *permp = highp;
          while (*permp && *permp++ != ' ')
            ;

          if (!*permp)
            fatal("permission separator not found in /proc/%u/maps", t->pid);

          char *permpe = permp;
          while (*permpe && *++permpe != ' ')
            ;

          if (!*permpe)
            fatal("permission end separator not found in /proc/%u/maps",
                  t->pid);

          char perms[5] = {0};
          if ((permpe - permp) != 4)
            fatal("permission is in unexpected format for /proc/%u/maps",
                  t->pid);

          strncpy(perms, permp, 4);

          char *namest = permpe;
          while (*namest && *namest++ != '/')
            ;

          char name_buf[PATH_MAX] = {0};
          strcpy(name_buf, namest);

          // Cut out the newline character
          int nb_len = strlen(name_buf);
          if (name_buf[nb_len - 1] == '\n')
            name_buf[nb_len - 1] = '\0';

          range.low = strtoull(line, NULL, 16);
          range.high = strtoull(highp, NULL, 16);
          snprintf(fname, sizeof(fname), "%s/%s_segment-%lu.dump", dump_dir,
                   prefix, segment_count++);

          strb_printf(log,
                      "    { \"low\": %llu, \"high\": %llu, \"dump\": \"%s\", "
                      "\"name\": \"/%s\", \"perms\": \"%s\" }",
                      range.low, range.high, fname, name_buf, perms);

          dump_memory(t->pid, fname, &range);
        }
      }
      if (line)
        free(line);
      fclose(fd);

      strb_puts(log, "\n  ]\n");
      strb_puts(log, "}");

      free((void *)exe);

      wb_add_strb(logbuf, log_fname, log);
      strb_destroy(log);
    } // otherwise, no idea what BP it is
  }
  }
}

/* -- TEMPLATE syscall hooking method for supporting new applications --

static void post_call_dump_heap_APPNAME(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);

  // MODIFY below conditional with the READ/WRITE syscall name used by your
application
  // e.g. raw syscall identifiers, or the C constant id-name mappings such as
__NR_read, __NR_recvmsg
  // Also modify the socket file descriptor parameters.
  // Can be determined manually from strace logs, or using iolearn.py script
provided

  if (syscall == __NR_read && sock_fd == 4) || (syscall == __NR_write && sock_fd
== 4)) { if (get_heap_maps(t->pid, &heap) == -1) { return;
    }

    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
dnum, session_id, syscall_name(syscall));

    // MODIFY name of syscalls accordingly

    logger_new_dump(logger, dpath, (syscall == __NR_read) ? "READ" : "WRITE",
dnum++); dump_memory(t->pid, dpath, &heap);
  } else if (syscall == __NR_accept) {
    socketmap_add(sockmap, t->pid, get_syscall_result(t));
  }
}
*/

static void post_call_dump_heap_dropbear(trace_t *t, void *data) {
  //fprintf(stderr, "POST: START - ");
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);

  if ((syscall == __NR_read && sock_fd == 5)) {
    //fprintf(stderr, "OURS - ");
    if (get_heap_maps(t->pid, &heap) == -1) { fprintf(stderr, "POST: HEAP ERROR\n"); return;    }

    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
++dnum, session_id, syscall_name(syscall));

    // MODIFY name of syscalls accordingly
    logger_new_dump_buffered(logger, dpath, "READ", dnum);
    dump_memory(t->pid, dpath, &heap);
    //fprintf(stderr, "mem dumped success\n");
  } else {
    //fprintf(stderr, "ignoring\n");
  }

}

static void pre_call_dump_heap_dropbear(trace_t *t, void *data) {
  //fprintf(stderr, "PRE: START - ");
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);

  if ((syscall == __NR_writev && sock_fd == 5)) {
    //fprintf(stderr, "OURS - ");
    if (get_heap_maps(t->pid, &heap) == -1) {fprintf(stderr, "PRE: HEAP ERROR\n"); return;    }

    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
++dnum, session_id, syscall_name(syscall));

    // MODIFY name of syscalls accordingly
    logger_new_dump_buffered(logger, dpath, "WRITEV", dnum);
    dump_memory(t->pid, dpath, &heap);
    //fprintf(stderr, "mem dumped success\n");
  } else {
    //fprintf(stderr, "ignoring\n");
  }
}

static void post_call_dump_heap_openssh(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);
  // e.g. raw syscall identifiers, or the C constant id-name mappings such as
  if ((syscall == __NR_read && sock_fd == 3)) { 
    if (get_heap_maps(t->pid, &heap) == -1) { return;    }
    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
++dnum, session_id, syscall_name(syscall));

    // MODIFY name of syscalls accordingly
    logger_new_dump_buffered(logger, dpath, "READ", dnum);
    dump_memory(t->pid, dpath, &heap);
    fprintf(stderr, "POST: mem dumped success\n"); 
  }

}

static void pre_call_dump_heap_openssh(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);

  if ((syscall == __NR_write && sock_fd == 3)) { 
    if (get_heap_maps(t->pid, &heap) == -1) { return;    }

    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
++dnum, session_id, syscall_name(syscall));

    // MODIFY name of syscalls accordingly
    logger_new_dump_buffered(logger, dpath, "WRITE", dnum);
    dump_memory(t->pid, dpath, &heap);
    fprintf(stderr, "PRE: mem dumped success\n");
  }
}

static void post_call_dump_heap_wolfssl_client(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);
  // e.g. raw syscall identifiers, or the C constant id-name mappings such as
  if ((syscall == __NR_recvfrom && sock_fd == 3)) {
    if (get_heap_maps(t->pid, &heap) == -1) { return;    }
    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
++dnum, session_id, syscall_name(syscall));

    // MODIFY name of syscalls accordingly
    logger_new_dump_buffered(logger, dpath, "READ", dnum);
    dump_memory(t->pid, dpath, &heap);
    fprintf(stderr, "POST: mem dumped success\n");
  } else if (syscall == __NR_recvfrom) {
    fprintf(stderr, "recvfrom %zu\n", sock_fd);
  }

}

static void pre_call_dump_heap_wolfssl_client(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);

  if ((syscall == __NR_sendto && sock_fd == 3)) {
    if (get_heap_maps(t->pid, &heap) == -1) { return; }

    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
++dnum, session_id, syscall_name(syscall));

    // MODIFY name of syscalls accordingly
    logger_new_dump_buffered(logger, dpath, "WRITE", dnum);
    dump_memory(t->pid, dpath, &heap);
    fprintf(stderr, "PRE: mem dumped success\n");
  } else if (syscall == __NR_sendto) {
    fprintf(stderr, "sendto %zu\n", sock_fd);
  }
}

static void post_call_dump_heap_wolfssl_server(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);
  // e.g. raw syscall identifiers, or the C constant id-name mappings such as
  if ((syscall == __NR_recvfrom && sock_fd == 3)) {
    if (get_heap_maps(t->pid, &heap) == -1) { return; }
    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
++dnum, session_id, syscall_name(syscall));

    // MODIFY name of syscalls accordingly
    logger_new_dump_buffered(logger, dpath, "READ", dnum);
    dump_memory(t->pid, dpath, &heap);
    fprintf(stderr, "POST: mem dumped success\n");
  } else if (syscall == __NR_recvfrom) {
    fprintf(stderr, "recvfrom %zu\n", sock_fd);
  }

}

static void pre_call_dump_heap_wolfssl_server(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);

  if ((syscall == __NR_sendto && sock_fd == 4)) { 
    if (get_heap_maps(t->pid, &heap) == -1) { return;    }

    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
++dnum, session_id, syscall_name(syscall));

    // MODIFY name of syscalls accordingly
    logger_new_dump_buffered(logger, dpath, "WRITE", dnum);
    dump_memory(t->pid, dpath, &heap);
    fprintf(stderr, "PRE: mem dumped success\n");
  } else if (syscall == __NR_sendto) {
    fprintf(stderr, "sendto %zu\n", sock_fd);
  }
}

static void pre_call_dump_heap_gnutls(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);
  static char write_dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

#if 0
  // todo: we also see can write here
  if (syscall == __NR_select) {
    fd_set *can_read = (fd_set *)get_syscall_arg(t, 1);
    fd_set *can_write = (fd_set *)get_syscall_arg(t, 2);

    if (can_read) {
      fd_set fds;
      memload(t->pid, &fds, can_read, sizeof(fd_set));

      if (FD_ISSET(6, &fds)) {
        if (*write_dpath != 0) {
          if (get_heap_maps(t->pid, &heap) == -1) {
            return;
          }
          dump_memory(t->pid, write_dpath, &heap);
          *write_dpath = 0;
        }
      }
    }
    if (can_write) {
      fd_set fds;
      memload(t->pid, &fds, can_write, sizeof(fd_set));

      if (FD_ISSET(6, &fds)) {
        if (get_heap_maps(t->pid, &heap) == -1) {
          return;
        }
        snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw",
                 dump_dir, ++dnum, session_id, syscall_name(syscall));
        logger_new_dump_buffered(logger, dpath, "SELECT", dnum);
        dump_memory(t->pid, dpath, &heap);
      }
    }
  }
#endif

  if (syscall == __NR_writev && sock_fd == 6) {
    if (get_heap_maps(t->pid, &heap) == -1) {
      return;
    }
    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
             ++dnum, session_id, syscall_name(syscall));
    logger_new_dump_buffered(logger, dpath, "WRITE", dnum);
    strcpy(write_dpath, dpath);
    dump_memory(t->pid, write_dpath, &heap);
  }
}

static void post_call_dump_heap_gnutls(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  // ssize_t result = get_syscall_result(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);

  // can read from fd == 6
  if (syscall == __NR_select && get_syscall_result(t) > 0 &&
      get_syscall_arg(t, 1) != 0) {
    fd_set fds;
    memload(t->pid, &fds, (fd_set *)get_syscall_arg(t, 1), sizeof(fd_set));

    if (FD_ISSET(6, &fds)) {
      if (get_heap_maps(t->pid, &heap) == -1) {
        return;
      }

      snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
               ++dnum, session_id, syscall_name(syscall));
      logger_new_dump_buffered(logger, dpath, "SELECT", dnum);
      dump_memory(t->pid, dpath, &heap);
    }
    return;
  }

  if ((syscall == __NR_recvfrom) && sock_fd == 6) {
    if (get_heap_maps(t->pid, &heap) == -1) {
      return;
    }
    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
             ++dnum, session_id, syscall_name(syscall));
    logger_new_dump_buffered(logger, dpath, "READ", dnum);
    dump_memory(t->pid, dpath, &heap);
  }
}


static void pre_call_dump_heap_openssl(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  static char write_dpath[PATH_MAX] = {0};
  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);
  map_range_t heap = {0};

  if ((syscall == __NR_read && sock_fd == 4) ) {
    if (*write_dpath != 0) {
      if (get_heap_maps(t->pid, &heap) == -1) {
        return;
      }
      dump_memory(t->pid, write_dpath, &heap);
      *write_dpath = 0;
    }
  }

  if (syscall == __NR_shutdown && sock_fd == 4) {
    if (get_heap_maps(t->pid, &heap) == -1) {
      return;
    }
    // do the pre-dump;
    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
             ++dnum, session_id, syscall_name(syscall));
    logger_new_dump_buffered(logger, dpath, "CLOSE", dnum);
    strcpy(write_dpath, dpath);
    dump_memory(t->pid, write_dpath, &heap);
    return;
  }

  if (syscall == __NR_write && sock_fd == 4) {
    if (get_heap_maps(t->pid, &heap) == -1) {
      return;
    }
    // do the pre-dump;
    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
             ++dnum, session_id, syscall_name(syscall));
    logger_new_dump_buffered(logger, dpath, "WRITE", dnum);
    strcpy(write_dpath, dpath);
    dump_memory(t->pid, write_dpath, &heap);
  }
}

static void post_call_dump_heap_openssl(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);

  if ( (syscall == __NR_read && sock_fd == 4)) {
    if (get_heap_maps(t->pid, &heap) == -1) {
      return;
    }

    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
             ++dnum, session_id, syscall_name(syscall));

    logger_new_dump_buffered(logger, dpath, "READ", dnum);

    dump_memory(t->pid, dpath, &heap);
  }
}

static void pre_call_dump_heap_exampleProtocol(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  static char write_dpath[PATH_MAX] = {0};
  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);
  map_range_t heap = {0};

  /* NOTE:
   * A pre-call hook is required for two reason:
   * 1) To give the state learner a normalised view of a protocol implementation
   *    irrespective of if it makes state modifications before or after a write
   *    operation. To do this, on the write event itself, we log that a write has
   *    happened and perform a dump (see the post-call hook), if the write
   *    is proceeded by a read operation, we replace the dump we made with a new
   *    dump at that point, this ensures we have captured the state transition.
   * 2) When we have a flow, where there is no natural teardown of the connection,
   *    we will miss the last modification to memory if the state transition
   *    occurs after the last write operation. Fortunately, since in most cases a
   *    non-natural teardown occurs due to an incomplete protocol run
   *    (e.g., INIT, AUTH), the target will block waiting for a new input, thus we
   *    perform a dump on that read event to get the state updates, it needs to
   *    happen as a pre-call, otherwise we will have to wait until a timeout occurs
   *    for the post-call hook to trigger.
   */

  if ((syscall == __NR_read && sock_fd >= 4)) {
    cached_fd = sock_fd;
    if (*write_dpath != 0) {
      if (get_heap_maps(t->pid, &heap) == -1) {
        return;
      }
      dump_memory(t->pid, write_dpath, &heap);
      *write_dpath = 0;
    }
  }

  if (syscall == __NR_sendto && sock_fd >= 4) {
    if (get_heap_maps(t->pid, &heap) == -1) {
      return;
    }
    // do the pre-dump;
    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
             ++dnum, session_id, syscall_name(syscall));
    logger_new_dump_buffered(logger, dpath, "WRITE", dnum);
    // cache the dump path in a local static
    strcpy(write_dpath, dpath);
    dump_memory(t->pid, write_dpath, &heap);
  } 

  if(syscall == __NR_shutdown && sock_fd == cached_fd) {
    if (get_heap_maps(t->pid, &heap) == -1) {
      return;
    }
    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
             ++dnum, session_id, syscall_name(syscall));
    logger_new_dump_buffered(logger, dpath, "WRITE", dnum);
    dump_memory(t->pid, dpath, &heap);
  }
}

static void post_call_dump_heap_exampleProtocol(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);

  /* NOTE:
   * A post-call hook is required if we need to analyse the return value of a given
   * syscall for success. It also ensures that reads are logged just after they have
   * happened (i.e., they haven't failed -- likely we should check the return to make
   * sure of this).
   */

  if (syscall == __NR_read && sock_fd >= 4) {
    if (get_heap_maps(t->pid, &heap) == -1) {
      return;
    }

    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
             ++dnum, session_id, syscall_name(syscall));

    logger_new_dump_buffered(logger, dpath, "READ", dnum);

    /* NOTE:
     * This will dump for all monitored syscalls meeting the above criteria. We cannot log
     * writes in a post-hook since it causes a race between the state learner's I/O (ctrl)
     * log and the dump log generated, which ultimately can lead to incorrect generation of
     * meta logs.
     *
     * For this protocol, since we check no return values, we could probably move the logic
     * into just the pre-hook.
     */

    dump_memory(t->pid, dpath, &heap);
  }
}


/*
 * The system calls that Hostap uses can depend on various factors. In our case
 * it uses netlink sockets (nl80211) to send/receive management frames, and
 * sendto and recvfrom syscalls for EAPOL frames.
 */

static void pre_call_dump_heap_hostapd(trace_t *t, void *data) {
    char dpath[PATH_MAX] = {0};
    int syscall = get_syscall(t);
    static char write_dpath_hostapd[PATH_MAX] = {0};
    ssize_t sock_fd = get_syscall_arg(t, 0);
    map_range_t heap = {0};
    Frame frame = Frame_None;

    // Overwrite a previous write dump with the dump taken at a call of select
    if (syscall == __NR_select && get_syscall_arg(t, 1) != 0) {
      fd_set fds;
      memload(t->pid, &fds, (fd_set *)get_syscall_arg(t, 1), sizeof(fd_set));

      if ((FD_ISSET(6, &fds)) || (FD_ISSET(12, &fds))) {
        if (*write_dpath_hostapd != 0) {
          if (get_heap_maps(t->pid, &heap) == -1) {
            return;
          }
          dump_memory(t->pid, write_dpath_hostapd, &heap);
          //TODO should we put logger_new_dump call here??
          *write_dpath_hostapd = 0;
          return;
        }
      }
    }

    if (syscall == __NR_sendmsg && sock_fd == 5)
    {
        frame = monitor_sendmsg(t);
        if (frame == Frame_None || frame == Frame_Unknown) return;
        fprintf(stdout, "[sendmsg] frame = %s\n", frame2str(frame));
    }

    if (syscall == __NR_sendto && sock_fd == 11)
    {
        struct sockaddr_ll dest_addr;
        off_t dest_addr_ex = get_syscall_arg(t, 4);
        read_memory(t->pid, &dest_addr, sizeof(dest_addr), dest_addr_ex);

        if (dest_addr.sll_protocol == htons(ETH_P_PAE)) {
            fprintf(stdout, "[sendto] EAPOL\n");
            frame = Frame_Eapol;
        }
    }

    if (frame != Frame_None)
    {
        if (get_heap_maps(t->pid, &heap) == -1)
            return;

        snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
                 ++dnum, session_id, syscall_name(syscall));

        strcpy(write_dpath_hostapd, dpath);
        logger_new_dump_buffered(logger, dpath, "WRITE", dnum);

        dump_memory(t->pid, dpath, &heap);
    }


}

static void post_call_dump_heap_hostapd(trace_t *t, void *data) {
    char dpath[PATH_MAX] = {0};
    map_range_t heap = {0};
    int syscall = get_syscall(t);
    ssize_t sock_fd = get_syscall_arg(t, 0);
    Frame frame = Frame_None;

    // For Chris the sock_fd value was 6, while for Mathy it was 8?
    // We check both, monitor_recvmsg will ignore the incorrect one.
    if (syscall == __NR_recvmsg && (sock_fd == 6 || sock_fd == 8))
    {
        frame = monitor_recvmsg(t);
        if (frame != Frame_None)
            fprintf(stdout, "[recvmsg] frame = %s\n", frame2str(frame));
    }

    if (syscall == __NR_recvfrom && sock_fd == 12)
    {
        struct sockaddr_ll dest_addr;
        off_t dest_addr_ex = get_syscall_arg(t, 4);
        read_memory(t->pid, &dest_addr, sizeof(dest_addr), dest_addr_ex);

        if (dest_addr.sll_protocol == htons(ETH_P_PAE)) {
            fprintf(stdout, "[recvfrom] EAPOL\n");
            frame = Frame_Eapol;
        }
    }

    if (frame != Frame_None)
    {
        // This sleep is essential, otherwise learner will not work.
        // I'm not sure why this is the case...
        usleep(100 * 1000);

        if (get_heap_maps(t->pid, &heap) == -1)
            return;

        snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
                 ++dnum, session_id, syscall_name(syscall));
        logger_new_dump_buffered(logger, dpath, "READ", dnum);
        dump_memory(t->pid, dpath, &heap);

        /*
         * When we are receiving a Deauth frame to the learner, we log both a
         * READ and WRITE snapshot. I'm not sure if this still is needed.
         */
        if (frame == Frame_Deauth) {
          snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
                   ++dnum, session_id, syscall_name(syscall));
          logger_new_dump_buffered(logger, dpath, "WRITE", dnum);
          dump_memory(t->pid, dpath, &heap);
        }
    }
}

static void pre_call_dump_heap_hostapdtls(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  static char write_dpath[PATH_MAX] = {0};
  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);
  map_range_t heap = {0};

  if (sock_fd != 4)
    return;

  // To handle implementations which update the state after the write:
  // on the next "READ" sycall *overwrite* the post-syscall "WRITE"
  // memory dump. Variable write_dpath indicates if there previously
  // was a write syscall that was logged.
  if (syscall == __NR_recvfrom && *write_dpath != 0) {
    if (get_heap_maps(t->pid, &heap) == -1)
      return;

    dump_memory(t->pid, write_dpath, &heap);
    *write_dpath = 0;
  }

  // Log the timestamp of the "WRITE" syscall pre-syscall to assure the
  // timestamp occurs before the learner receives it.
  if (syscall == __NR_sendto) {
    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
             dnum, session_id, syscall_name(syscall));
    logger_new_dump_buffered(logger, dpath, "WRITE", dnum);
    strcpy(write_dpath, dpath);
  }
}

static void post_call_dump_heap_hostapdtls(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);

  if (sock_fd != 4)
    return;

  if (syscall == __NR_recvfrom || syscall == __NR_sendto) {
    if (get_heap_maps(t->pid, &heap) == -1)
      return;

    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
             dnum, session_id, syscall_name(syscall));

    // We already logged the timestamp for the "WRITE" syscall to avoid race
    // conditions with the learner.
    if (syscall != __NR_sendto)
      logger_new_dump_buffered(logger, dpath, "READ", dnum);

    // Always dump the memory post-syscall of "READ" and "WRITE"
    dump_memory(t->pid, dpath, &heap);

    // Next time save the memory dump to a new file. Note that dnum should
    // only be updated here, to assure the logged timestamp/filename in the
    // pre-syscall hook still corresponds to the dump made post-syscall.
    dnum++;
  }
}

static void pre_call_dump_heap_hostapdtls_client(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  static char write_dpath[PATH_MAX] = {0};
  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);
  map_range_t heap = {0};

  if (sock_fd != 3)
    return;

  // To handle implementations which update the state after the write:
  // on the next "READ" sycall *overwrite* the post-syscall "WRITE"
  // memory dump. Variable write_dpath indicates if there previously
  // was a write syscall that was logged.
  if (syscall == __NR_recvfrom && *write_dpath != 0) {
    if (get_heap_maps(t->pid, &heap) == -1)
      return;

    dump_memory(t->pid, write_dpath, &heap);
    *write_dpath = 0;
  }

  // Log the timestamp of the "WRITE" syscall pre-syscall to assure the
  // timestamp occurs before the learner receives it.
  if (syscall == __NR_sendto) {
    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
             dnum, session_id, syscall_name(syscall));
    logger_new_dump_buffered(logger, dpath, "WRITE", dnum);
    strcpy(write_dpath, dpath);
  }
}

static void post_call_dump_heap_hostapdtls_client(trace_t *t, void *data) {
  char dpath[PATH_MAX] = {0};
  map_range_t heap = {0};

  int syscall = get_syscall(t);
  ssize_t sock_fd = get_syscall_arg(t, 0);

  if (sock_fd != 3)
    return;

  if (syscall == __NR_recvfrom || syscall == __NR_sendto /*|| syscall == __NR_close*/) {
    if (get_heap_maps(t->pid, &heap) == -1)
      return;

    snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
             dnum, session_id, syscall_name(syscall));

    // - We already logged the timestamp for the "WRITE" syscall to avoid race
    //   conditions with the learner.
    if (syscall != __NR_sendto)
      logger_new_dump_buffered(logger, dpath, syscall == __NR_recvfrom ? "READ" : "WRITE", dnum);

    // Always dump the memory post-syscall of "READ" and "WRITE"
    dump_memory(t->pid, dpath, &heap);

    // Next time save the memory dump to a new file. Note that dnum should
    // only be updated here, to assure the logged timestamp/filename in the
    // pre-syscall hook still corresponds to the dump made post-syscall.
    dnum++;
  }
}

static void pre_call_dump_heap_iwd(trace_t *t, void *data)
{
    char dpath[PATH_MAX] = {0};
    map_range_t heap = {0};
    int syscall = get_syscall(t);
    ssize_t sock_fd_arg = get_syscall_arg(t, 0);
    Frame frame = Frame_None;

    if (syscall == __NR_sendto && sock_fd_arg == 4)
    {
        off_t nlh_ex = get_syscall_arg(t, 1);
        size_t nlh_len = get_syscall_arg(t, 2);
        struct nlmsghdr *nlh = malloc(nlh_len);
        read_memory(t->pid, nlh, nlh_len, nlh_ex);

        frame = process_netlink_msg(nlh);

        free(nlh);
    }

    //if (frame == Frame_AssocReq /*|| frame == Frame_AssocResp*/ || frame == Frame_Eapol)
    if (frame != Frame_None && frame != Frame_Error)
    {
        if (get_heap_maps(t->pid, &heap) == -1)
            return;

        snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
                 ++dnum, session_id, syscall_name(syscall));

        logger_new_dump_buffered(logger, dpath, "WRITE", dnum);

        dump_memory(t->pid, dpath, &heap);

        // This sleep doesn't appear important
        //usleep(100 * 1000);
    }
}

static void post_call_dump_heap_iwd(trace_t *t, void *data)
{
    char dpath[PATH_MAX] = {0};
    map_range_t heap = {0};
    int syscall = get_syscall(t);
    ssize_t sock_fd_arg = get_syscall_arg(t, 0);
    Frame frame = Frame_None;

    if (syscall == __NR_recvmsg && sock_fd_arg == 4)
    {
        frame = monitor_recvmsg(t);
    }

    if (frame != Frame_None && frame != Frame_Error)
    {
        // This sleep is essential, otherwise learner will not work.
        // I'm not sure why this is the case...
        usleep(100 * 1000);

        if (get_heap_maps(t->pid, &heap) == -1)
            return;

        snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
                 ++dnum, session_id, syscall_name(syscall));
        logger_new_dump_buffered(logger, dpath, "READ", dnum);
        dump_memory(t->pid, dpath, &heap);

        // When we are sending a Deauth frame to the learner (TODO: Check direction of frame),
        // this means we received a disallowed frame, and replied using a deauth. This means
        // we must log both a READ and a WRITE for compatibility with the learner.
        if (frame == Frame_Deauth || frame == Frame_Unexpected) {
          snprintf(dpath, sizeof(dpath), "%s/dumpID-%lu_sessID-%d_%s.raw", dump_dir,
                   ++dnum, session_id, syscall_name(syscall));
          logger_new_dump_buffered(logger, dpath, "WRITE", dnum);
          dump_memory(t->pid, dpath, &heap);
        }
    }
}

static inline void print_usage_and_die(char *prog_name) {
  fprintf(stderr,
          "usage: %s [-app <openssl, hostapd>] [-session-id <session-id>] "
          "[-trace-malloc <log-file>] [-save-mappings] [-watchpoint "
          "<base-address> <base-alloc-size> <address> <size>]* "
          "[-watchpoint-dump-min <id>] [-watchpoint-dump-max <id>] [-watchpoint-malloc-trace <log-file>] "
          "[-pid <pid>|command args...]\n",
          prog_name);
  exit(EXIT_FAILURE);
}

void closedown(int sig_num) {
  //detach_all();

  static int closed_before = 0;

  if (closed_before) {
    return;
  }

  closed_before = 1;

  wb_add_strb(logbuf, logger_path, logger);
  strb_destroy(logger);

  if (mallocs) {
    wb_add_strb(logbuf, mallocs_path, mallocs);
    strb_destroy(mallocs);
  }

  if (dynalign) {
    // NOTE: this will also flush the log to logbuf
    malign_destroy(dynalign);
  }

  wb_flush_buffers(logbuf);
  wb_destroy(logbuf);

  exit(EXIT_SUCCESS);
}

void atclose() {
  closedown(0);
}

unsigned long long hstrtoull(const char *str) {
  if (str[0] && str[0] == '0' && str[1] && (str[1] | 0x20) == 'x') {
    str += 2;
    return strtoull(str, NULL, 16);
  } else {
    return strtoull(str, NULL, 10);
  }
}

int main(int argc, char **argv) {
  debug_init(stderr);
  char *prog_name = argv[0];
  pid_t pid = -1;
  const char *malloc_log = NULL;
  const char *w_malloc_log = NULL;
  bool save_mappings = false;

  for (argv++; *argv && **argv == '-'; argv++) {
    if (strcmp(*argv, "--") == 0) {
      argv++;
      break;
    } else if (strcmp(*argv, "-pid") == 0) {
      if (!*argv++)
        print_usage_and_die(prog_name);
      pid = atoi(*argv);
    } else if (strcmp(*argv, "-session-id") == 0) {
      if (!*argv++)
        print_usage_and_die(prog_name);
      session_id = atoi(*argv);
    } else if (strcmp(*argv, "-signal-attach") == 0) {
      signal_attach = 1;
    } else if (strcmp(*argv, "-trace-malloc") == 0) {
      malloc_log = *++argv;
    } else if (strcmp(*argv, "-dump-dir") == 0) {
      dump_dir = *++argv;
    } else if (strcmp(*argv, "-malloc-zerod") == 0) {
      opt_zero_mem = true;
    } else if (strcmp(*argv, "-malloc-ffed") == 0 && opt_zero_mem == false) {
      opt_ff_mem = true;
    } else if (strcmp(*argv, "-save-mappings") == 0) {
      save_mappings = true;
    } else if (strcmp(*argv, "-watchpoint") == 0) {
      if (watchpoint_count < MAX_BREAKPOINTS) {
        uint64_t base_address = (uint64_t)hstrtoull(*++argv);
        size_t alloc_size = (size_t)hstrtoull(*++argv);
        intptr_t address = (long long)hstrtoull(*++argv);

        watchpoints[watchpoint_count++] = (watchpoint_t){
            .base_address = base_address,
            .alloc_size = alloc_size,
            .address = address,
            .aligned_address = address,
            .size = atoi(*++argv),
        };
      } else {
        fprintf(stderr, "error: maximum number of watchpoints is %u.",
                MAX_BREAKPOINTS);
        exit(EXIT_FAILURE);
      }
    } else if (strcmp(*argv, "-watchpoint-dump-min") == 0) {
      wdnum_min = strtol(*++argv, NULL, 10);
    } else if (strcmp(*argv, "-watchpoint-dump-max") == 0) {
      wdnum_max = strtol(*++argv, NULL, 10);
    } else if (strcmp(*argv, "-watchpoint-malloc-trace") == 0) {
      w_malloc_log = *++argv;
    } else if (strcmp(*argv, "-app") == 0) {
      app = *++argv;
      if (!(strcmp(app, "openssl") == 0 || strcmp(app, "hostapd") == 0 ||
            strcmp(app, "gnutls") == 0 || strcmp(app, "protocolBasic") == 0 ||
            strcmp(app, "wolfssl_client") == 0 || strcmp(app, "wolfssl_server") == 0 ||
            strcmp(app, "duplicate") == 0 ||
            strcmp(app, "hostaptls_srv") == 0 ||  strcmp(app, "hostaptls_cli") == 0 ||
            strcmp(app, "iwd") == 0 || strcmp(app, "ssl_server") == 0 ||
            strcmp(app, "tls_ext_server") == 0 ||
            strcmp(app, "openssh") == 0 ||
            strncmp(app, "dropbear", 8) == 0)) {
        print_usage_and_die(prog_name);
      }
    } else {
      print_usage_and_die(prog_name);
    }
  }
  if (dump_dir == NULL)
    fatal("need to specify -dump-dir filepath for logs & snapshots");

  if (pid == -1) {
    char pid_raw[10];
    char cmd[30];
    if (strcmp(app, "openssh") == 0) {
      snprintf(cmd, 11, "pgrep %s", "sshd");
    } else if (strcmp(app, "wolfssl_client") == 0) {
      snprintf(cmd, 18, "pgrep \"^client\"");
    } else if (strcmp(app, "wolfssl_server") == 0) {
      snprintf(cmd, 18, "pgrep \"^server\"");
    } else {
      snprintf(cmd, 30, "pgrep %s", app);
    }

    FILE *pid_fd = popen(cmd, "r");

    if (fgets(pid_raw, 10, pid_fd) != NULL)
      pid = strtoul(pid_raw, NULL, 10);

    pclose(pid_fd);
    fprintf(stderr, "PID_RAW: %s\n", pid_raw);
  }

  //if (pid == -1){
  //  fatal("Failed to set PID.");
  //} else {
  //  fprintf(stderr, "FOUND PID:%u\n", pid);
  //}

  // Set up logger
  snprintf(logger_path, PATH_MAX, "%s/dump%d.log", dump_dir, session_id);
  logbuf = wb_init();
  assert(logbuf != NULL);
  logger = strb_init();
  assert(logger != NULL);

  if (pid != -1 && save_mappings) {
    char mem_maps[PATH_MAX] = {0};
    snprintf(mem_maps, PATH_MAX, "%s/mem_maps%d.log", dump_dir, session_id);
    write_mem_maps(pid, mem_maps);
  }

  if (watchpoint_count > 0) {
    if (!w_malloc_log) {
      fatal("no malloc trace log specified; required for dynamic watchpoint "
            "alignment");
    }
    char w_malloc_log_dir[PATH_MAX] = {0};
    snprintf(w_malloc_log_dir, PATH_MAX, "%s/%s", dump_dir, w_malloc_log);
    char malloc_log_dir[PATH_MAX] = {0};
    snprintf(malloc_log_dir, PATH_MAX, "%s/%s", dump_dir, malloc_log);
    if (!(dynalign =
          malign_init(logbuf, w_malloc_log_dir, watchpoints, watchpoint_count,
                      MALLOC_BP_END, malloc_log_dir))) {
      fatal("cannot initialise malloc aligner using %s", w_malloc_log);
    };
  }

  tracer_plugin_t plug;
  if (strcmp(app, "openssl") == 0) {
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_openssl,
        .post_call = post_call_dump_heap_openssl,
        .pid_selector = any_pid,
        .data = NULL,
    };
  } else if (strcmp(app, "ssl_server") == 0) {
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_openssl,
        .post_call = post_call_dump_heap_openssl,
        .pid_selector = any_pid,
        .data = NULL,
    };
  } else if (strcmp(app, "hostapd") == 0) {
    // TODO: add pre-call hook for writes
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_hostapd,
        .post_call = post_call_dump_heap_hostapd,
        .pid_selector = any_pid,
        .data = NULL,
    };
  } else if (strcmp(app, "gnutls") == 0) {
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_gnutls,
        .post_call = post_call_dump_heap_gnutls,
        .pid_selector = any_pid,
        .data = NULL,
    };
  } else if (strcmp(app, "protocolBasic") == 0) {
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_exampleProtocol,
        .post_call = post_call_dump_heap_exampleProtocol,
        .pid_selector = any_pid,
        .data = NULL,
    };
  } else if (strcmp(app, "hostaptls_srv") == 0) {
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_hostapdtls,
        .post_call = post_call_dump_heap_hostapdtls,
        .pid_selector = any_pid,
        .data = NULL,
    };
  } else if (strcmp(app, "hostaptls_cli") == 0) {
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_hostapdtls_client,
        .post_call = post_call_dump_heap_hostapdtls_client,
        .pid_selector = any_pid,
        .data = NULL,
    };
  } else if (strcmp(app, "iwd") == 0) {
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_iwd,
        .post_call = post_call_dump_heap_iwd,
        .pid_selector = any_pid,
        .data = NULL,
    };
  } else if (strcmp(app, "tls_ext_server") == 0) {
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_openssl,
        .post_call = post_call_dump_heap_openssl,
        .pid_selector = any_pid,
        .data = NULL,
    };
  } else if (strcmp(app, "openssh") == 0) {
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_openssh,
        .post_call = post_call_dump_heap_openssh,
        .pid_selector = any_pid,
        .data = NULL,
    };
  } else if (strcmp(app, "dropbear") == 0) {
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_dropbear,
        .post_call = post_call_dump_heap_dropbear,
        .pid_selector = any_pid,
        .data = NULL,
    };
  } else if (strcmp(app, "wolfssl_server") == 0) {
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_wolfssl_server,
        .post_call = post_call_dump_heap_wolfssl_server,
        .pid_selector = any_pid,
        .data = NULL,
    };
  } else if (strcmp(app, "wolfssl_client") == 0) {
    plug = (tracer_plugin_t){
        .pre_call = pre_call_dump_heap_wolfssl_client,
        .post_call = post_call_dump_heap_wolfssl_client,
        .pid_selector = any_pid,
        .data = NULL,
    };
  }

  // Since getting the nl80211 id may fail, only get it when needed
  if (strcmp(app, "hostapd") == 0 || strcmp(app, "iwd") == 0)
  {
    if (init_nl80211_id() < 0) {
      fprintf(stderr, "Failed to get nl80211 interface ID, exiting.\n");
      exit(1);
    }
  }

  if (malloc_log) {
    snprintf(mallocs_path, PATH_MAX, "%s/%s", dump_dir, malloc_log);
    if (!(mallocs = strb_init())) {
      fatal("cannot initialise mallocs logging buffer");
    }
    plug.pid_selector = trace_malloc_pid;
    // plug.data = (void *)plug.post_call;
    // plug.post_call = trace_malloc_post_call;
    plug.start = trace_malloc_init;
    plug.exec = trace_malloc_exec;
    plug.detach = trace_malloc_detach;
    plug.breakpoint = trace_malloc_hit;
  }
  if (dynalign && watchpoint_count > 0) {
    plug.start = trace_malloc_init;
    plug.exec = trace_malloc_exec;
    plug.breakpoint = watchpoints_hit;
    plug.detach = trace_malloc_detach;
  }

  if (pid == -1) {
    if (!*argv) {
      print_usage_and_die(prog_name);
    } else {
      fprintf(stderr, "launching via: %s", argv[0]);
      pid = run_traceable(argv[0], argv, 1, 0);
      fprintf(stderr, "got pid: %d", pid);
    }
  } else {
    trace_attach(pid);
  }

  atexit(atclose);

  signal(SIGABRT, closedown);
  signal(SIGILL, closedown);
  signal(SIGQUIT, closedown);
  signal(SIGINT, closedown);
  signal(SIGTERM, closedown);
  signal(SIGKILL, closedown);

  trace(pid, &plug);

  exit(EXIT_SUCCESS);
}

// ex:set ts=2
