#ifndef STATEMEM_WRITEBUFFER_H_
#define STATEMEM_WRITEBUFFER_H_

#include <stddef.h>

typedef void logbuf_t;
typedef void stringbuf_t;

extern logbuf_t *wb_init(void);
extern void wb_add_bytes(logbuf_t *wb, const char *file,
                         const unsigned char *bytes, size_t count);
extern void wb_reinit(logbuf_t *wb, const char *file);
extern void wb_add_str(logbuf_t *wb, const char *file, const char *str);
extern void wb_add_strb(logbuf_t *wb, const char *file,
                        const stringbuf_t *strb);
extern void wb_flush_buffers(logbuf_t *);
extern void wb_destroy(logbuf_t *);

extern stringbuf_t *strb_init(void);
extern void strb_puts(stringbuf_t *strb, const char *str);
extern void strb_printf(stringbuf_t *strb, const char *fmt, ...);
extern void strb_destroy(stringbuf_t *strb);

extern void logger_new_dump_buffered(stringbuf_t *strb, const char *name, const char *type,
                                     int num);

#endif
