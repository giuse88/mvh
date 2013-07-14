#ifndef COLOR_H
#define COLOR_H

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#ifdef COLOR 
  #define DPRINT_RED(fmt, args...) do { \
      fprintf(stdout,ANSI_COLOR_RED fmt ANSI_COLOR_RESET, ##args); \
      } while (0)
  #define DPRINT_GREEN(fmt, args...) do { \
      fprintf(stdout,ANSI_COLOR_GREEN fmt ANSI_COLOR_RESET, ##args);\
      } while (0)
#else 
  #define DPRINT_RED  ( args...) do {} while(0)
  #define DPRINT_GREEN( args...) do {} while(0)  
#endif

#endif /* end of include guard: COLOR_H */


