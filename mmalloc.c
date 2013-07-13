#include "mmalloc.h"

#include <sys/mman.h>

#include "abstract_data/kernel.h"
#include "debug.h"

#include <sys/ptrace.h> 

#include "linux_syscall_support.h"

/**
 * Align to the nearest lower address
 *
 * @param size Address or size to be aligned.
 * @param align Size of alignment, must be power of 2.
 */
#define ALIGN_DOWN(size, align) ((size) & ~((align) - 1))

/**
 * Align to the nearest higher address
 *
 * @param size Address or size to be aligned.
 * @param align Size of alignment, must be power of 2.
 */
#define ALIGN_UP(size, align) (((size) + ((align) - 1)) & ~((align) - 1))

/** Default memory alignment used */
#define MMALLOC_ALIGNMENT 8

/** Default memory allocation quantum */
#define MMALLOC_QUANTUM (1 << 16)  //4096

struct mheader {
  size_t size;
  size_t used;
  void *bump;
};

static struct mheader *last = NULL;

void *mmalloc(size_t size) {
  //dprint("size %zu\n", size);

  size = ALIGN_UP(size, MMALLOC_ALIGNMENT);
  if (last) {
    size_t avail = (void *)last + last->size - last->bump;
    if (avail >= size) {
      void *p = last->bump;
      last->bump = last->bump + size;
      last->used += size;
      return p;
    }
  }

  // We need a bit more to have a space for header structure.
  size_t len = ALIGN_UP(size + sizeof(struct mheader), MMALLOC_QUANTUM);

  // Allocate new header through mmap system call.
  struct mheader *header = (struct mheader *)mmap(NULL, len,
      PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (header == MAP_FAILED) {
    return NULL;
  }

  if (len - sizeof(struct mheader) - size >= MMALLOC_ALIGNMENT) {
    last = header;
  }

  header->size = len;
  header->used = size;
  void *p = (void *)header + sizeof(struct mheader);
  header->bump = p + size;

  return p;
}

void mfree(void *ptr, size_t size) {
  if (!ptr)
    return;

  size_t len = ALIGN_UP(size, MMALLOC_ALIGNMENT);

  void *p = (void *) ALIGN_DOWN((uintptr_t)ptr, MMALLOC_QUANTUM);
  struct mheader *header = (struct mheader *)p;
  header->used -= len;

  // Free header after last allocation has been freed.
  if (!header->used) {
    munmap(header, header->size);
  }
}
