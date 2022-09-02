#include <asm/unistd_64.h>
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct map_range {
  unsigned long long low, high;
} map_range_t;

static inline void fatal(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);

  fputc('\n', stderr);
  exit(EXIT_FAILURE);
}

static inline int get_maps(pid_t pid, const char *name, map_range_t *range) {
  char path[PATH_MAX], *line = NULL;
  size_t line_max = 0;
  bool multi_range_start = false;

  snprintf(path, sizeof(path), "/proc/%u/maps", pid);

  FILE *fd = fopen(path, "r");
  if (!fd) {
    fatal("cannot open /proc/%u/maps", pid);
  }

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

uint64_t resolve_libc_function(pid_t pid, const char *func) {
  map_range_t range = {0};
  if (get_maps(pid, "libc-", &range) == -1) {
    fatal("no libc found in maps for %d", pid);
  }

  char path[PATH_MAX] = {0};
  snprintf(path, sizeof(path), "/proc/%u/mem", pid);

  FILE *fdi = fopen(path, "rb");
  if (!fdi)
    fatal("cannot open /proc/%u/mem", pid);

  unsigned long long size = range.high - range.low;
  fseeko(fdi, range.low, SEEK_SET);

  unsigned char *buf = (unsigned char *)malloc(size);
  if (!buf)
    fatal("cannot allocate buffer to process libc");

  if (fread(buf, 1, size, fdi) != size)
    fatal("error fetching process memory: %llx - %llx", range.low, range.high);

  fclose(fdi);

  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buf;
  Elf64_Phdr *phdr = (Elf64_Phdr *)(buf + ehdr->e_phoff);

  //printf("phdrs @ offset: %lx; size: %llx\n", ehdr->e_phoff, size);

  uint64_t min_offset = UINT64_MAX;

  //printf("processing program headers... %d\n", ehdr->e_phnum);
  for (Elf64_Half i = 0; i < ehdr->e_phnum; ++i) {
    if (phdr->p_type == PT_LOAD) {
      min_offset = min_offset > phdr->p_vaddr ? phdr->p_vaddr : min_offset;
      //printf("PT_LOAD found; min_offset = %lx\n", min_offset);
    }

    if (phdr->p_type == PT_DYNAMIC) {
      //printf("PT_DYNAMIC found\n");
      size_t dyns_num = phdr->p_memsz / sizeof(Elf64_Dyn);
      Elf64_Dyn *dyns = (Elf64_Dyn *)(buf + phdr->p_vaddr - min_offset);

      Elf64_Sym *symtab = NULL;
      char *strtab = NULL;
      size_t sym_count = 0;

      //printf("walking dynamic entries; found %zu\n", dyns_num);
      for (size_t di = 0; di < dyns_num; ++di) {
        //printf("d_tag: %lx\n", dyns->d_tag);
        if (dyns->d_tag == DT_SYMTAB) {
          //printf("DT_SYMTAB found\n");
          symtab = (Elf64_Sym *)(buf + dyns->d_un.d_ptr - min_offset - range.low);
        } else if (dyns->d_tag == DT_STRTAB) {
          //printf("DT_STRTAB found\n");
          strtab = (char *)(buf + dyns->d_un.d_ptr - min_offset - range.low);
        } else if (dyns->d_tag == DT_HASH) {
          typedef struct {
            uint32_t nbucket;
            uint32_t nchain;
          } hash_hdr_t;
          hash_hdr_t *ht = (hash_hdr_t *)(buf + dyns->d_un.d_ptr - min_offset - range.low);
          sym_count = ht->nchain;
          //printf("DT_HASH found; number of symbols: %zu\n", sym_count);
        } else if (dyns->d_tag == DT_GNU_HASH) {
          //printf("DT_GNU_HASH found...\n");
          // see:
          // https://chromium-review.googlesource.com/c/crashpad/crashpad/+/876879/18/snapshot/elf/elf_image_reader.cc
          typedef struct {
            uint32_t nbuckets;
            uint32_t symoffset;
            uint32_t bloom_size;
            uint32_t bloom_shift;
          } ghash_hdr_t;
          ghash_hdr_t *ght =
              (ghash_hdr_t *)(buf + dyns->d_un.d_ptr - min_offset - range.low);
          uint32_t *buckets =
              (uint32_t *)((unsigned char *)ght + sizeof(ghash_hdr_t) +
                           sizeof(uint64_t) * ght->bloom_size);
          uint32_t last_sym = 0;
          //printf("walking buckets...\n");
          for (size_t bi = 0; bi < ght->nbuckets; ++bi) {
            last_sym = last_sym < buckets[bi] ? buckets[bi] : last_sym;
          }
          if (last_sym < ght->symoffset) {
            sym_count = last_sym;
            //printf("last_sym less than symoffset; number of symbols: %zu\n",
            //       sym_count);
          } else {
            //printf("last_sym greater than symoffset; walking chains...\n");
            uint32_t *chains = (uint32_t *)((unsigned char *)buckets +
                                            (sizeof(*buckets) * ght->nbuckets));
            for (;;) {
              uint32_t ent =
                  *(uint32_t *)((unsigned char *)chains +
                                (last_sym - ght->symoffset) * sizeof(*chains));
              //printf("chain entry: %x...\n", ent);
              last_sym += 1;
              if (ent & 1)
                break;
            }
            sym_count = last_sym;
            //printf("number of symbols: %zu\n", sym_count);
          }
        }
        if (symtab && strtab && sym_count)
          break;
        dyns++;
      }

      if (!symtab || !strtab || !sym_count)
        fatal("cannot find symbol/string tables to resolve %s", func);

      //printf("walking symbol table...\n");
      for (size_t symi = 0; symi < sym_count; ++symi) {
        size_t st_idx = symtab->st_name;
        const char *sym_name = (const char *)(strtab + st_idx);
        if (!strcmp(sym_name, func)) {
          //printf("%s @ offset %lx\n", func, symtab->st_value);
          return symtab->st_value - min_offset + range.low;
        }
        symtab++;
      }
      return 0;
    }
    phdr = (Elf64_Phdr *)((unsigned char *)phdr + ehdr->e_phentsize);
  }
  return 0;
}
