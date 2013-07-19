#ifndef UTILS_H
#define UTILS_H

#include "handler.h" 
#include <sys/types.h> 

#define IS_STD_FD(arg) ( ( arg == STDOUT_FILENO) || \
                         ( arg == STDERR_FILENO) || \
                         ( arg ==  STDIN_FILENO) )


ssize_t receive_result_with_extra (int, struct syscall_result *, char *, size_t); 
ssize_t send_result_with_extra    (int, struct syscall_result *, char *, size_t); 
ssize_t receive_extra(int , char * , size_t ); 
ssize_t send_extra   (int , char * , size_t); 


#endif /* end of include guard: UTILS_H */
