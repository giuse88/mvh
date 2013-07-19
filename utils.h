#ifndef UTILS_H
#define UTILS_H

#include "handler.h" 
#include <sys/types.h> 

int receive_result_with_extra
    (int fd, struct syscall_result * result, int extra_size, char * buf); 

int send_result_with_extra
    (int fd, struct syscall_result * result, int extra_size, char * buf); 

ssize_t receive_extra(int , char * , size_t ); 
ssize_t send_extra   (int , char * , size_t); 


#endif /* end of include guard: UTILS_H */
