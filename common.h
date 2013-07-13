#ifndef COMMON_H
#define COMMON_H

#include "error.h"
#include "debug.h"
#include "conf.h" 

#ifndef INTERNAL
  #define INTERNAL __attribute__((visibility("internal")))
#endif

#define INTR(x) ({ int i__; while ((i__ = (x)) < 0 && errno == EINTR); i__;})
#define INTR_RES(x,y) ({ int i__; y=0;  while ((i__ = (x)) < 0 && errno == EINTR){ y+=i__; }; y+=i__;})

#define ALWAYS 1
#define OVERWRITE 1 

#endif /* end of include guard: COMMON_H */
