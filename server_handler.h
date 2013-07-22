#ifndef SERVER_HANDLER_H 
#define SERVER_HANDLER_H

#include "mvh_server.h"
#include "handler.h" 
#include <fcntl.h> 
#include <poll.h>

struct server_handler {
    void   (*handler)( struct thread_group *, const struct syscall_header *, const struct syscall_header *); 
}; 

extern struct server_handler * syscall_table_server_; 

void initialize_server_handler(); 

#endif /* end of include guard: SERVER_HANDLER_H */
