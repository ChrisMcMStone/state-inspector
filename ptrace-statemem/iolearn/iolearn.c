#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <time.h>

// ptrace-burrito
#include "debug.h"
#include "debug_syscalls.h"
#include "errors.h"
#include "process.h"
#include "trace.h"
#include "util.h"

static int session_id = 0;
static FILE *io_log = NULL;

static inline void fatal(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);

  fputc('\n', stderr);
  exit(EXIT_FAILURE);
}

static inline void do_log(FILE *fp, const char *fmt, ...)
{
  va_list args;
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  unsigned long long ns =
      (unsigned long long)(ts.tv_sec) * 1000000000 +
      (unsigned long long)(ts.tv_nsec);
  fprintf(fp, "%llu ", ns);

  va_start(args, fmt);
  vfprintf(fp, fmt, args);
  va_end(args);
  fputc('\n', fp);
}

static void post_call(trace_t *t, void *data)
{
  int syscall = get_syscall(t);

  /* METHOD:

     1) Monitor all socket calls that are of type SOCK_STREAM and push them to a set
     2) Monitor all accept calls; if fd in socket set, then move to accept set
     3) Monitor all read/write type calls; if fd in accept set, log type R or W with bytes
        read/written with fd
     4) Monitor all close calls; if fd in socket set, remove; if fd in accept set,
        remove

     fds to monitor will be written to log and correspond with read/written bytes from
     test program (e.g., happy path for openssl learner)
   */

  if (syscall == __NR_socket) {
    int sock_fd = get_syscall_result(t);
    int sock_type = get_syscall_arg(t, 1);

    do_log(io_log, "SOCKET %d %d", sock_fd, sock_type);
  } else if (syscall == __NR_accept || syscall == __NR_accept4) {
    int sock_fd = get_syscall_result(t);
    int sock_listen_fd = get_syscall_arg(t, 0);

    do_log(io_log, "ACCEPT %d %d", sock_fd, sock_listen_fd);
  } else if (syscall == __NR_read || syscall == __NR_recvfrom || syscall == __NR_recvmsg || syscall == __NR_readv) {
    int sock_handle_fd = get_syscall_arg(t, 0);
    int sock_io_length = get_syscall_result(t);

    // TYPE FD LEN
    do_log(io_log, "READ %d %d %d", syscall, sock_handle_fd, sock_io_length);
  } else if (syscall == __NR_sendmsg || syscall == __NR_sendto || syscall == __NR_write || syscall == __NR_writev) {
    int sock_handle_fd = get_syscall_arg(t, 0);
    int sock_io_length = get_syscall_result(t);

    // TYPE FD LEN
    do_log(io_log, "WRITE %d %d %d", syscall, sock_handle_fd, sock_io_length);
  } else if (syscall == __NR_close) {
    int sock_fd = get_syscall_arg(t, 0);
    do_log(io_log, "CLOSE %d", sock_fd);
  }
}

static inline void print_usage_and_die(char *prog_name)
{
  fprintf(stderr, "usage: %s [-session-id <session-id>] [-pid <pid>|command args...]\n", prog_name);
  exit(EXIT_FAILURE);
}

void closedown(int sig_num) {

  if (io_log) fclose(io_log);
  detach_all();
  exit(EXIT_SUCCESS);

}

int main(int argc, char **argv)
{
  debug_init(stderr);
  char *prog_name = argv[0];
  char io_log_fname[32] = { 0 };
  pid_t pid = -1;

  for (argv++; *argv && **argv == '-'; argv++) {
    if (strcmp(*argv, "--") == 0) {
      argv++;
      break;
    }  else if (strcmp(*argv, "-pid") == 0) {
      if (!*argv++) print_usage_and_die(prog_name);
      pid = atoi(*argv);
    } else if (strcmp(*argv, "-session-id" ) == 0) {
      if ( !*argv++ ) print_usage_and_die(prog_name);
      session_id = atoi(*argv);
    } else {
      print_usage_and_die(prog_name);
    }
  }

  snprintf(io_log_fname, sizeof(io_log_fname), "io_%d.log", session_id);
  if (!(io_log = fopen(io_log_fname, "w"))) {
    fatal("unable to open I/O log at %s for writing", io_log_fname);
  }

  tracer_plugin_t plug = {
    .post_call = post_call,
    .pid_selector = any_pid,
    .data = NULL,
  };

  if (pid == -1) {
    if (!*argv) {
      print_usage_and_die(prog_name);
    } else {
      pid = run_traceable(argv[0], argv, 1, 0);
    }
  } else {
    trace_attach(pid);
  }

  signal(SIGINT, closedown);

  trace(pid, &plug);

  exit(EXIT_SUCCESS);
}
