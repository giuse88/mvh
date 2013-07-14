#ifndef DEBUG_H_
#define DEBUG_H_

#include <stdio.h> 
#include <string.h> 

typedef enum {
  DEBUG_FATAL,
  DEBUG_ERROR,
  DEBUG_WARNING,
  DEBUG_INFO,
  DEBUG_ALL
} debug_message_level;

#ifdef DEBUG
  #define DPRINT(level, fmt, args...) do { \
      if ((level) <= DEBUG_WARNING) {\
          fprintf(stderr, "%s:%d " fmt, __FILE__, __LINE__, ##args); \
          break;\
      }\
         if ((level) == DEBUG_INFO )  \
           fprintf(stderr, "[DEBUG_INFO] " fmt, ##args); \
         if ((level) == DEBUG_ALL )  \
           fprintf(stderr,fmt, ##args); \
      } while (0)
#else
  #define DPRINT(level, fmt, args...) do { } while (0)
#endif



#endif /* DEBUG_H_ */
