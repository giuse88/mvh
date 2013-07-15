#ifndef HANDLER_H
#define HANDLER_H

#include <ucontext.h> 

#include "trusted_thread.h"

//Default
void sys_request_default(syscall_request *, const ucontext_t *); 
void sys_result_default(const syscall_request *);
void trusted_default (const syscall_request *); 

//open 
void sys_request_open(syscall_request *, const ucontext_t * ); 


#endif /* end of include guard: HANDLER_H */
