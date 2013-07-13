#ifndef MMALLOC_H_
#define MMALLOC_H_

#include <stddef.h>

extern void *mmalloc(size_t size);
extern void mfree(void *ptr, size_t size);

#endif /* MMALLOC_H_ */
