#ifndef UTILS_H
#define UTILS_H

#include "handler.h" 
#include <sys/types.h> 

#define IS_STD_FD(arg) ( ( arg == STDOUT_FILENO) || \
                         ( arg == STDERR_FILENO) || \
                         ( arg ==  STDIN_FILENO) )

#define CHECK(__transfered, __size, __result) assert( ((size_t)__transfered == __size) || (((int)__result < 0) && ((size_t)__transfered == SIZE_RESULT)))

ssize_t receive_result_with_extra (int, struct syscall_result *, char *, size_t); 
ssize_t send_result_with_extra    (int, struct syscall_result *, char *, size_t); 
ssize_t receive_extra(int , char * , size_t ); 
ssize_t send_extra   (int , char * , size_t); 
void    get_extra_arguments( int, char*, int, char *, size_t); 
size_t  get_size_from_cmd(int request);

#endif /* end of include guard: UTILS_H */
