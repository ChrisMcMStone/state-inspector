#pragma once

#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#define LOG_EV_DUMP "LOG_WRITE"  // <ts> LOG_WRITE <file>
#define LOG_EV_IN   "LOG_INPUT"  // <ts> LOG_INPUT <label>
#define LOG_EV_OUT  "LOG_OUTPUT" // <ts> LOG_OUTPUT <label>

typedef FILE *logger_t;

extern logger_t logger_new(const char *output);
extern bool logger_ok(logger_t t);
extern void logger_drop(logger_t *t);
extern void logger_new_dump(logger_t t, const char *name, const char *type, int num);
extern int64_t logger_get_monotone();
