#ifndef MAPS_H_
#define MAPS_H_

#include <elf.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>

#include <sys/types.h>

#include "abstract_data/hlist.h"
#include "abstract_data/list.h"
#include "abstract_data/rbtree.h"
#include "abstract_data/jhash.h"
#include "mmalloc.h"

#if defined(__x86_64__)
typedef Elf64_Addr Elf_Addr;
#elif defined(__i386__)
typedef Elf32_Addr Elf_Addr;
#else
#error Undefined target platform
#endif

/** Process memory regions */
enum region_type {
  REGION_EXECUTABLE = 0x1,
  REGION_LIBRARY = 0x2,
  REGION_HEAP = 0x4,
  REGION_STACK = 0x8,
  REGION_BSS = 0x10,
  REGION_VDSO = 0x20,
  REGION_VSYSCALL = 0x40,
  REGION_ALL = 0x7F,
};

struct maps {
  int fd;
  char *vsyscall;
  struct hlist_head *library_hash;
};

/** Region obtained via /proc/<pid>/maps */
struct region {
  /** Region start address */
  void *start;
  /** Region end address */
  void *end;
  /** Region size */
  size_t size;
  /** Access protection */
  int perms;
  /** Region offset */
  Elf_Addr offset;
  /** Device identifier */
  dev_t dev;
  /** Device inode */
  ino_t inode;
  /** Associated pathname */
  const char *pathname;
  /** Region type */
  enum region_type type;
  /** Regions tree */
  struct rb_node rb_region;
};



extern void maps_init(struct maps *maps, int fd);
#if 0
extern struct maps *maps_read(struct maps *maps, enum region_type level);
#endif
extern int maps_read(struct maps *maps);
extern void *maps_alloc_near(void *addr, size_t size, int prot);

#define library_hashfn(n) jhash(n, strlen(n), 0) & (libraryhash_size - 1)
#define libraryhash_size 16
#define libraryhash_shift 4

#define libraryhash_entry(node) hlist_entry((node), struct library, library_hash)

/**
 * Iterate over hash table elements of given type.
 *
 * @param tpos type pointer to use as a loop cursor
 * @param pos entry pointer to use as a loop cursor
 * @param table your table
 * @param member the name of the enry within the struct
 */
#define for_each_library(lib, maps) \
    for (int i = 0; i < libraryhash_size; ++i) \
        for (lib = libraryhash_entry((maps)->library_hash[i].first); \
             &lib->library_hash; \
             lib = libraryhash_entry(lib->library_hash.next))

#endif /* MAPS_H_ */
