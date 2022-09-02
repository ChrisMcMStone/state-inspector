#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/time.h>

#include "logger.h"

logger_t logger_new(const char *output)
{
  FILE *f = fopen(output, "w");
  return f;
}

bool logger_ok(logger_t t)
{
  return t != NULL;
}

void logger_drop(logger_t *t)
{
  if (*t) fclose(*t);
  *t = NULL;
}

int64_t logger_get_monotone() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000 * 1000 * 1000 + ts.tv_nsec;
}

void logger_new_dump(logger_t t, const char *name, const char *type, int num)
{
  /*
  struct timeval tv; gettimeofday(&tv, NULL);

  unsigned long long milliseconds_since_epoch =
    (unsigned long long)(tv.tv_sec) * 1000 +
    (unsigned long long)(tv.tv_usec) / 1000;
  */

  int64_t monotone = logger_get_monotone();

  fprintf(t, "%" PRIi64 " " LOG_EV_DUMP " %s %s %d\n" , monotone, name, type, num);
  fflush(t);
}
