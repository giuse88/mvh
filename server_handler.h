#ifndef SERVER_HANDLER_H 
#define SERVER_HANDLER_H

#include "handler.h" 

struct server_handler {
    void   (*handler)(const syscall_request *, const syscall_request *); 
}; 

extern struct server_handler * syscall_table_server_; 

void initialize_server_handler(); 

#endif /* end of include guard: SERVER_HANDLER_H */
