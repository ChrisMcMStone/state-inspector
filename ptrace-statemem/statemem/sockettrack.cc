#include <cstddef>
#include <map>
#include <mutex>
#include <set>
#include <sys/types.h>

struct socketmap_t {
  std::map<pid_t, std::set<int>> map;
  std::mutex lock;

  socketmap_t() : map{}, lock{} { }

  void insert(pid_t pid, int fd) {
    this->lock.lock();
    auto search = this->map.find(pid);
    if (search != std::end(this->map)) {
      search->second.insert(fd);
    } else {
      auto fds = std::set<int>();
      fds.insert(fd);
      this->map.insert({ pid, std::move(fds) });
    }
    this->lock.unlock();
  }

  bool exists(pid_t pid, int fd) {
    this->lock.lock();
    auto search = this->map.find(pid);
    auto ret = false;
    if (search != std::end(this->map)) {
      ret = search->second.find(fd) != search->second.end();
    }
    this->lock.unlock();
    return ret;
  }
};

extern "C" {

socketmap_t *socketmap_init(void) {
  return new (std::nothrow) socketmap_t();
}

void socketmap_destroy(socketmap_t *t) {
  delete t;
}

void socketmap_add(socketmap_t *t, pid_t pid, int fd) {
  t->insert(pid, fd);
}

bool socketmap_exists(socketmap_t *t, pid_t pid, int fd) {
  return t->exists(pid, fd);
}

};
