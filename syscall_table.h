#ifndef SYSCALL_TABLE_H__
#define SYSCALL_TABLE_H__

#include <sys/types.h>
#include "handler.h"
#include "common.h" 

struct syscall_handler {
  // handler executes when the application make a request for a system call
  u64_t     (*handler_untrusted)(const ucontext_t *); 
  //handler executed by the trusted thread when it receives a request 
  void     (*handler_trusted)( const syscall_request *, int fd); 
};

/* INTERFACE */
extern struct syscall_handler * syscall_table_;
void initialize_syscall_table();  

#endif // SYSCALL_TABLE_H__
