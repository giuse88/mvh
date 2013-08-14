#ifndef COMMON_H
#define COMMON_H

#include "error.h"
#include "debug.h"
#include "conf.h" 

#define __USE_GNU 1
#include <ucontext.h>

#ifndef INTERNAL
  #define INTERNAL __attribute__((visibility("internal")))
#endif

#define INTR(x) ({ int i__; while ((i__ = (x)) < 0 && errno == EINTR); i__;})
#define INTR_RES(x,y) ({ int i__; y=0;  while ((i__ = (x)) < 0 && errno == EINTR){ y+=i__; }; y+=i__;})
#define ASYNC_CALL(x,y) do { y=x; if (y < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue; else break; }while(1)

#define ALWAYS 1
#define OVERWRITE 1 

#if  defined (__x86_64__)
  #define MAX_SYSTEM_CALL 312  
#else 
  #error Architecture not supported
#endif

#define RESET(x,y) memset(x, 0, sizeof(y))
#define RESET_2(x,y) memset(x, 0, y)

typedef unsigned long u64_t; 
extern char * syscall_names []; 

#endif /* end of include guard: COMMON_H */
