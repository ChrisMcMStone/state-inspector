#include <algorithm>
#include <cstdarg>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <new>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

extern "C" {
  #include "logger.h"
}

class WriteBuffer {
public:
  WriteBuffer() { }
  ~WriteBuffer() {
    for (auto &[_name, content] : file_to_content) {
      std::ignore = _name; // ignore complier warning on unused _name var
      delete content;
    }
  }

  std::vector<unsigned char> *content(const char *name) {
    std::string key(name);
    if (auto it = file_to_content.find(name); it == std::end(file_to_content)) {
      file_to_content[name] = new std::vector<unsigned char>();
    }
    return file_to_content[name];
  }

  void flush_all() {
    for (auto &[name, contents] : file_to_content) {
      std::ofstream ofs(name, std::ios::out | std::ios::binary);
      if (!ofs.good()) continue; // likely we should log this...
      ofs.write(reinterpret_cast<const char *>(contents->data()), std::size(*contents));
      ofs.flush();
      ofs.close();
    }
  }
private:
  std::unordered_map<std::string, std::vector<unsigned char> *> file_to_content;
};

extern "C" {
  WriteBuffer *wb_init() {
    return new (std::nothrow) WriteBuffer();
  }

  void wb_reinit(WriteBuffer* wb, const char *file) {
    wb->content(file)->clear();
  }

  void wb_add_bytes(WriteBuffer *wb, const char *file, const unsigned char *bytes, size_t count) {
    std::copy(bytes, bytes+count, std::back_inserter(*wb->content(file)));
  }

  void wb_add_str(WriteBuffer *wb, const char *file, const char *str) {
    std::copy(str, str+strlen(str), std::back_inserter(*wb->content(file)));
  }

  void wb_add_strb(WriteBuffer *wb, const char *file, const std::stringstream* strb) {
    auto str = strb->str();
    wb_add_str(wb, file, str.c_str());
  }

  void wb_flush_buffers(WriteBuffer *wb) {
    wb->flush_all();
  }

  void wb_destroy(WriteBuffer *wb) {
    delete wb;
  }
}

extern "C" {
  std::stringstream *strb_init() {
    return new (std::nothrow) std::stringstream();
  }

  void strb_puts(std::stringstream *strb, const char *str) {
    *strb << str;
  }

  void strb_printf(std::stringstream *strb, const char *fmt, ...) {
    char str[8192] = { 0 };

    std::va_list va;
    va_start(va, fmt);
    vsnprintf(str, sizeof(str)-1, fmt, va);
    va_end(va);

    *strb << str;
  }

  void strb_destroy(std::stringstream *strb) {
    delete strb;
  }
}

extern "C" {
  void logger_new_dump_buffered(std::stringstream *strb, const char *name,
                                const char *type, int num) {
    int64_t monotone = logger_get_monotone();
    char str[8192] = {0};

    snprintf(str, sizeof(str) - 1, "%" PRIi64 " " LOG_EV_DUMP " %s %s %d\n",
            monotone, name, type, num);
    *strb << str;
  }
}
