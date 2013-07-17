#ifndef SERVER_HANDLER_H 
#define SERVER_HANDLER_H

#include "handler.h" 
#include <fcntl.h> 
#include <poll.h> 

struct server_handler {
    void   (*handler)(int [], struct pollfd [], const struct syscall_header *, const struct syscall_header *); 
}; 

extern struct server_handler * syscall_table_server_; 

void initialize_server_handler(); 

#endif /* end of include guard: SERVER_HANDLER_H */
