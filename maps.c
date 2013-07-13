#include "maps.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/limits.h>
#include <sys/mman.h> 

#include "abstract_data/hlist.h"
#include "abstract_data/list.h"
#include "abstract_data/rbtree.h"
#include "abstract_data/jhash.h"
#include "mmalloc.h"


#include "common.h"
#include "library.h"

#include "sandbox.h"
extern struct sandbox_info sandbox; 

#define MAX_LINKBUF_SIZE PATH_MAX
#define MAX_BUF_SIZE PATH_MAX + 1024

static inline struct library *library_find(struct hlist_head *hash, const char *pathname) {
  struct hlist_head *head;
  struct hlist_node *node;
  struct library *l;

  head = &hash[library_hashfn(pathname)];
  hlist_for_each_entry(l, node, head, library_hash) {
    if (strcmp(l->pathname, pathname) == 0)
      return l;
  }

  return NULL;
}

static inline void library_add(struct hlist_head *hash, struct library *lib) {
  struct hlist_head *head;
  struct hlist_node *node;
  struct library *l;

  head = &hash[library_hashfn(lib->pathname)];
  hlist_for_each_entry(l, node, head, library_hash) {
    if (strcmp(l->pathname, lib->pathname) == 0)
      return;
  }

  hlist_add_head(&lib->library_hash, head);
}

static inline struct region *__rb_insert_region(struct library *library, Elf_Addr offset, int prot, struct rb_node *node) {
  struct rb_node **p = &library->rb_region.rb_node;
  struct rb_node *parent = NULL;
  struct region *region;

  while (*p) {
    parent = *p;
    region = rb_entry(parent, struct region, rb_region);

    if (offset > region->offset)
      p = &(*p)->rb_left;
    else if (offset < region->offset)
      p = &(*p)->rb_right;
    else if (prot & PROT_EXEC)
      return region;
  }

  rb_link_node(node, parent, p);

  return NULL;
}

static inline struct region *rb_insert_region(struct library *library, Elf_Addr offset, int prot, struct rb_node *node) {
  struct region *ret;
  if ((ret = __rb_insert_region(library, offset, prot, node)))
    goto out;
  rb_insert_color(node, &library->rb_region);
out:
  return ret;
}

inline void maps_init(struct maps *maps, int fd) {
  maps->fd = fd;
  maps->vsyscall = 0;
  maps->library_hash = mmalloc(sizeof(struct hlist_head) * libraryhash_size);
  for (int i = 0; i < libraryhash_size; i++)
    INIT_HLIST_HEAD(&maps->library_hash[i]);
}

int maps_read(struct maps *maps) {
  
  if (lseek(maps->fd, 0, SEEK_SET) < 0)
    return -EIO;

  char buf[MAX_BUF_SIZE] = { '\0' };
  char *from = buf, *to = buf, *next = buf;
  char *bufend = buf + MAX_BUF_SIZE - 1;


  do {
    from = next; /* advance to the start of the next line */
    next = (char *)memchr(from, '\n', to - from); /* check if we have another line */
    if (!next) {
      /* shift/fill the buffer */
      size_t len = to - from;
      /* move the current text to the start of the buffer */
      memmove(buf, from, len);
      from = buf;
      to = buf + len;
      /* fill up buffer with text */
      size_t nread;
      while (to < bufend) {
        nread = read(maps->fd, to, bufend - to);
        if (nread > 0)
          to += nread;
        else
          break;
      }
      if (to != bufend && !nread)
        memset(to, 0, bufend - to); /* zero-out remaining space */
      *to = '\n'; /* sentinel */
      next = (char *)memchr(from, '\n', to + 1 - from);
    }
    *next = 0; /* turn newline into 0 */
    next += next < to ? 1 : 0; /* skip NULL if not end of text */

    unsigned long start, end;
    char flags[4], *pathname;
    unsigned long offset;
    int major, minor;
    long inode;
    int nameoff;

    // Parse each line of /proc/<pid>/maps file.
    if (sscanf(from, "%"SCNx64"-%"SCNx64" %4s %"SCNx64" %x:%x %"SCNd64" %n",
        &start, &end, flags, &offset, &major, &minor, &inode, &nameoff) > 6) {
      // Must have permissions to read and execute, and be non-zero size.
      if ((flags[0] == 'r') && (flags[2] == 'x') && ((end - start) > 0)) {
        /* allocate a new region structure */
        struct region *reg = (struct region *)mmalloc(sizeof(struct region));
        //assert(reg != NULL);

        // Create new region
        rb_init_node(&reg->rb_region);

        reg->start = (void *)start;
        reg->end = (void *)end;
        reg->size = (size_t)(end - start);

        // Setup protection permissions
        int perms = PROT_NONE;
        if (flags[0] == 'r')
          perms |= PROT_READ;
        if (flags[1] == 'w')
          perms |= PROT_WRITE;
        if (flags[2] == 'x')
          perms |= PROT_EXEC;

        if (flags[3] == 'p')
          perms |= MAP_PRIVATE;
        else if (flags[3] == 's')
          perms |= MAP_SHARED;
        reg->perms = perms;

        // Set region offset
        reg->offset = (Elf_Addr)offset;

        // Device and number
        reg->dev = minor | (major << 8);
        reg->inode = inode;

        // Save pathname
        if (nameoff == 0 || (size_t) nameoff > strlen(from)) {
          nameoff = strlen(from);
        }

        pathname = from + nameoff;

        if (strncmp(pathname, "[vdso]", 6) == 0) {
          // /proc/self/maps has a misleading file offset
          offset = 0;
          reg->type = REGION_VDSO;
        } else if (strncmp(pathname, "[vsyscall]", 10) == 0) {
          maps->vsyscall = (char *)start;
          reg->type = REGION_VSYSCALL;
        } else if (pathname[0] == '\0') {
          reg->type = REGION_BSS;
        } else {
          reg->type = REGION_LIBRARY;
          //char exename[128], linkbuf[MAX_LINKBUF_SIZE];
          //size_t linkbuf_size;

          //snprintf(exename, sizeof(exename), "/proc/%u/exe", pid);
          //if ((linkbuf_size = readlink(exename, linkbuf, MAX_LINKBUF_SIZE)) > 0)
          //  linkbuf[linkbuf_size] = 0;
          //else
          //  linkbuf[0] = 0;

          //if (strncmp(pathname, linkbuf, MAX_LINKBUF_SIZE) == 0)
          //  reg->type = REGION_EXECUTABLE;
          //else
          //  reg->type = REGION_LIBRARY;
        }
        //reg->pathname = strdup(pathname); /* TODO: avoid strdup (becasue of malloc) */

        struct library *lib = library_find(maps->library_hash, pathname);
        if (!lib) {
          lib = mmalloc(sizeof(*lib));
          library_init(lib, pathname, maps);
          library_add(maps->library_hash, lib);
          DPRINT(DEBUG_ALL, "library %s\n", lib->pathname);
        }

        rb_insert_region(lib, offset, perms, &reg->rb_region);
        if (reg->type & REGION_VDSO)
          lib->vdso = true;
      }
    }
  } while (to > buf);

  return 0;
}


#define MAX_DISTANCE (1536 << 20)
#define PAGE_ALIGNMENT 4096

void *maps_alloc_near(void *addr, size_t size, int prot) {

 //  
  if (lseek(sandbox.self_maps, 0, SEEK_SET) < 0)
    return NULL;

  // We try to allocate memory within 1.5GB of a target address. This means, we
  // will be able to perform relative 32bit jumps from the target address.
  size = ALIGN(size, PAGE_ALIGNMENT);

  // Go over each line of /proc/self/maps and consider each mapped region one
  // at a time, looking for a gap between regions to allocate.
  char buf[MAX_BUF_SIZE] = { '\0' };
  char *from = buf, *to = buf, *next = buf;
  char *bufend = buf + MAX_BUF_SIZE - 1;

  unsigned long gap_start = 0x10000;

  do {
    from = next; /* advance to the start of the next line */
    next = (char *)memchr(from, '\n', to - from); /* check if we have another line */
    if (!next) {
      /* shift/fill the buffer */
      size_t len = to - from;
      /* move the current text to the start of the buffer */
      memmove(buf, from, len);
      from = buf;
      to = buf + len;
      /* fill up buffer with text */
      size_t nread;
      while (to < bufend) {
        nread = read(sandbox.self_maps, to, bufend - to);
  //      write (2, to, bufend - to);
        if (nread > 0)
          to += nread;
        else
          break;
      }
      if (to != bufend && !nread)
        memset(to, 0, bufend - to); /* zero-out remaining space */
      *to = '\n'; /* sentinel */
      next = (char *)memchr(from, '\n', to + 1 - from);
    }
    *next = 0; /* turn newline into 0 */
    next += next < to ? 1 : 0; /* skip NULL if not end of text */

    unsigned long gap_end, map_end;
    int name;

    // Parse each line of /proc/<pid>/maps file.
    if (sscanf(from, "%"SCNx64"-%"SCNx64" %*4s %*d %*x:%*x %*d %n", &gap_end, &map_end, &name) > 1) {
      // gap_start to gap_end now covers the region of empty space before the current line.
      // Now we try to see if there's a place within the gap we can use.
      if (gap_end - gap_start >= size) {
        // Is the gap before our target address?
        if (((long)addr - (long)gap_end >= 0)) {
          if ((long)addr - (gap_end - size) < MAX_DISTANCE) {
            if (name == 0 || (size_t) name > strlen(from)) {
              name = strlen(from);
            }
            char *pathname = from + name;
            //dprint("pathname %s\n", pathname);
            DPRINT(DEBUG_INFO, "%s\n", pathname);  
            unsigned long pos;
            if (strncmp(pathname, "[stack]", 7) == 0) {
              // Underflow protection when we're adjacent to the stack
              if ((uintptr_t) addr < MAX_DISTANCE || (uintptr_t) addr - MAX_DISTANCE < gap_start) {
                pos = gap_start;
              } else {
                pos = ((uintptr_t)addr - MAX_DISTANCE) & ~4095;
                if (pos < gap_start)
                  pos = gap_start;
              }
            } else {
              // Otherwise, take the end of the region
              pos = gap_end - size;
            }
            void *ptr = mmap((void *)pos, size, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (ptr != MAP_FAILED)
              return ptr;
          }
        } else if (gap_start + size - (uintptr_t)addr < MAX_DISTANCE) {
          // Gap is after the address, above checks that we can wrap around through 0 to a space we'd use
          void *ptr = mmap((void *)gap_start, size, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
          if (ptr != MAP_FAILED)
            return ptr;
        }
      }
      gap_start = map_end;
    }
  } while (to > buf);

  return NULL;
}
