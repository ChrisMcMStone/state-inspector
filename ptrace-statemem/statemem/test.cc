#define _FILE_OFFSET_BITS 64

#include <algorithm>
#include <cassert>
#include <ctime>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <vector>

extern "C" {
#include "statemem.h"
}

using wpaddr_t = uint64_t;

struct Alloc {
  enum class variant_t { Malloc, Free };
  using id_t = size_t;
  using timestamp_t = uint64_t;

  Alloc(const std::string &line) {
    auto cpos = 0;
    auto npos = line.find(' ');

    timestamp = std::stoull(line.substr(cpos, npos - cpos));

    cpos = npos + 1;
    npos = line.find(' ', cpos);

    auto ntok = line.substr(cpos, npos - cpos);

    if (ntok == "M") {
      kind = variant_t::Malloc;

      // pc
      cpos = npos + 1;
      npos = line.find(' ', cpos);
      pc = std::stoull(line.substr(cpos, npos - cpos), nullptr, 16);

      // arg
      cpos = npos + 1;
      npos = line.find(' ', cpos);
      arg = std::stoull(line.substr(cpos, npos - cpos), nullptr, 16);

      // ret
      cpos = npos + 1;
      npos = line.find(' ', cpos);
      ret = std::stoull(line.substr(cpos, npos - cpos), nullptr, 16);

    } else { // == "F"
      kind = variant_t::Free;

      // pc
      cpos = npos + 1;
      npos = line.find(' ', cpos);
      pc = std::stoull(line.substr(cpos, npos - cpos), nullptr, 16);

      // arg
      cpos = npos + 1;
      npos = line.find(' ', cpos);
      arg = std::stoull(line.substr(cpos, npos - cpos), nullptr, 16);
      ret = 0;
    }
  }

  bool is_malloc() const { return kind == variant_t::Malloc; }

  Alloc::variant_t kind;
  id_t id = 0;
  uint64_t arg, ret, pc, timestamp;
  int lifetime_count = 0;

  friend std::ostream &operator<<(std::ostream &os, const Alloc &alloc) {
    if (alloc.is_malloc()) {
      os << "Malloc(" << alloc.arg << ") = " << alloc.ret;
    } else {
      os << "Free(" << alloc.arg << ")";
    }
    return os;
  }
};

using lifetimes_t =
    std::map<uint64_t, std::pair<Alloc::id_t, std::optional<Alloc>>>;

std::pair<std::vector<Alloc>, lifetimes_t>
build_mallocs(std::istream &ifs, Alloc::timestamp_t max_timestamp) {
  std::string line;
  std::vector<Alloc> mallocs;
  lifetimes_t lifetimes;

  while (std::getline(ifs, line)) {
    auto alloc = Alloc(line);
    if (alloc.timestamp >= max_timestamp) {
      break;
    }
    if (alloc.is_malloc()) {
      auto v = std::make_pair(alloc.id, std::nullopt);
      lifetimes.insert({alloc.ret, std::move(v)});
      mallocs.push_back(std::move(alloc));
    } else if (alloc.arg == 0) {
      continue;
    } else {
      auto v = lifetimes.find(alloc.arg);
      if (v == lifetimes.end()) {
        continue;
      }
      v->second.second = std::optional(std::move(alloc));
    }
  }
  return {mallocs, lifetimes};
}

struct WInfo {
  size_t id;
  wpaddr_t base_address;
  size_t alloc_size;
  int size;
  std::optional<Alloc> alloc;
};

class DynAligner {
public:
  const size_t watchpoint_start;

  DynAligner() = delete;
  DynAligner(std::istream &is, const watchpoint_t *watchpoints,
             const size_t watchpoints_count, const size_t wp_start,
             const char *log_name = nullptr,
             Alloc::timestamp_t max_timestamp =
                 std::numeric_limits<Alloc::timestamp_t>::max())
      : watchpoint_start{wp_start} {
    if (log_name != nullptr) {
      output.open(log_name);
    }

    auto vals = build_mallocs(is, max_timestamp);
    std::copy(std::rbegin(vals.first), std::rend(vals.first),
              std::back_inserter(mallocs));
    // lifetimes = std::move(vals.second);
    last_n.push_back(std::size(mallocs));

    for (size_t i = 0; i < watchpoints_count; ++i) {
      watchpoint_mapping.insert(
          {static_cast<wpaddr_t>(watchpoints[i].address),
           WInfo{i + watchpoint_start, watchpoints[i].base_address, watchpoints[i].alloc_size, watchpoints[i].size, std::nullopt}});
    }
  }

  std::vector<std::tuple<Alloc::id_t, uint64_t, size_t>>
  process_malloc(uint64_t pc, uint64_t arg, uint64_t ret) {
    /*
      Cases:
      1) Match first
      2) Not match first

      Standard alignment aligns smallest against largest; here we do not
      know which log will be the largest; however, must make an alignment
      when we wish to query a watchpoint. In this case, we could buffer the
      alignment
     */

    if (this->output.is_open() && this->output.good()) {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      unsigned long long milliseconds_since_epoch =
          (unsigned long long)(tv.tv_sec) * 1000 +
          (unsigned long long)(tv.tv_usec) / 1000;

      this->output << std::dec << milliseconds_since_epoch << " M 0x"
                   << std::hex << pc << " 0x" << std::hex << arg << " 0x"
                   << std::hex << ret << std::endl;
    }

    auto vals = std::vector<std::tuple<Alloc::id_t, uint64_t, size_t>>();
    auto LIMIT = 100LL;
    auto pop_n = 0;

    for (ssize_t k = std::size(last_n) - 1;
         k >=
         std::max(0LL, static_cast<long long>(std::size(last_n)) - LIMIT - 1);
         --k) {
      for (ssize_t i = last_n[k] - 1; i >= 0; --i) {
        auto &alloc = mallocs[i];
        if (alloc.pc == pc && alloc.arg == arg) {
          std::cout << "M: 0x" << std::hex << pc << " 0x" << arg << std::endl;
          for (auto &[w, a] : watchpoint_mapping) {
            if (a.base_address == alloc.ret && a.alloc_size == alloc.arg && w + a.size <= alloc.ret + alloc.arg) {
              std::cout << "W: " << w << "  " << alloc.ret << std::endl;
              auto nwp = w - alloc.ret + ret;
              a.alloc = std::make_optional(alloc);
              vals.push_back(std::make_tuple(a.id, nwp, a.size));
            }
          }
          if (pop_n && static_cast<long long>(std::size(last_n)) < LIMIT) {
            last_n.erase(std::end(last_n) - pop_n, std::end(last_n));
          }
          last_n.push_back(i);
          return vals;
        }
      }
      ++pop_n;
    }
    return vals;
  }

  std::optional<Alloc::id_t> process_free(uint64_t pc, uint64_t arg) {
    if (this->output.is_open() && this->output.good()) {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      unsigned long long milliseconds_since_epoch =
          (unsigned long long)(tv.tv_sec) * 1000 +
          (unsigned long long)(tv.tv_usec) / 1000;

      this->output << std::dec << milliseconds_since_epoch << " F 0x"
                   << std::hex << pc << " 0x" << std::hex << arg << std::endl;
    }

    auto kv = alloc_mapping.find(arg);
    if (kv != alloc_mapping.end()) {
      auto id = watchpoint_mapping.find(kv->second)->first;

      alloc_mapping.erase(kv->first);
      watchpoint_mapping.find(kv->second)->second.alloc = std::nullopt;
      return std::make_optional(id);
    }
    return std::nullopt;
  }

private:
  bool is_first = true;
  std::vector<Alloc> mallocs;
  std::vector<ssize_t> last_n;
  // lifetimes_t lifetimes;
  std::map<wpaddr_t, WInfo> watchpoint_mapping;
  std::map<uint64_t, wpaddr_t> alloc_mapping;
  std::ofstream output;
};

int main() {
  auto ifs = std::ifstream("malloc1.log");
  auto ifs2 = std::ifstream("malloc2.log");

  auto vals = build_mallocs(ifs2, std::numeric_limits<Alloc::timestamp_t>::max());

  const watchpoint_t wps[] = {
    {0x55eb050d9940, 0x310, 0x55eb050d9950, 0, 1},
    {0x55eb050d9940, 0x310, 0x55eb050d9960, 0, 1},
    {0x55eb050d9940, 0x310, 0x55eb050d9980, 0, 1},
  };

  auto d = DynAligner(ifs, wps, 3, 0);
  for (auto& alloc : vals.first) {
    if (!alloc.is_malloc()) continue;
    auto v = d.process_malloc(alloc.pc, alloc.arg, alloc.ret);

    if (std::size(v) > 0) {
      for (auto& [id, addr, sz] : v) {
        std::cout << id << " " << std::hex << addr << " " << std::dec << sz
                  << std::endl;
      }
    }
  }

  return 0;
}
