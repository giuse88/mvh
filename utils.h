#ifndef UTILS_H
#define UTILS_H

#include "handler.h" 
#include <sys/types.h> 

#define IS_STD_FD(arg) ( ( arg == STDOUT_FILENO) || \
                         ( arg == STDERR_FILENO) || \
                         ( arg ==  STDIN_FILENO) )

#define CHECK(__transfered, __size, __extra) assert( ((size_t)__transfered == __size) || ((!__extra ) && ((size_t)__transfered == SIZE_RESULT)))

ssize_t receive_result_with_extra (int, struct syscall_result *, char *, size_t); 
ssize_t send_result_with_extra    (int, struct syscall_result *, char *, size_t); 
ssize_t receive_extra(int , char * , size_t ); 
ssize_t send_extra   (int , char * , size_t); 
ssize_t get_extra_arguments( int, char*, int, char *, size_t); 
size_t  get_size_from_cmd(int request);
ssize_t forward_syscall_request_with_extra(int fd,  const struct syscall_header * header, char * buf, size_t size);  

#endif /* end of include guard: UTILS_H */

