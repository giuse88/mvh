#ifndef COMMON_H
#define COMMON_H

#include "error.h"
#include "debug.h"

#ifndef INTERNAL
  #define INTERNAL __attribute__((visibility("internal")))
#endif


// Enviroment variables used by the main application 
// to comunicate with the LD+Preload object 
#define MVH_SERVER_IP           "MVH_SERVER_IP"
#define MVH_SERVER_PORT         "MVH_SERVER_PORT"
#define MVH_PROCESS_VISIBILITY  "MVH_PROCESS_VISIBILITY"

// Default configuration options
#define DEFAULT_IP              "127.0.0.1" 
#define DEFAULT_PORT            5555
#define PUBLIC_STRING           "public" 
#define PRIVATE_STRING          "private" 

#define INTR(x) ({ int i__; while ((i__ = (x)) < 0 && errno == EINTR); i__;})
#define INTR_RES(x,y) ({ int i__; y=0;  while ((i__ = (x)) < 0 && errno == EINTR){ y+=i__; }; y+=i__;})

#define ALWAYS 1
#define OVERWRITE 1 

#endif /* end of include guard: COMMON_H */
