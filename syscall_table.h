#ifndef SYSCALL_TABLE_H__
#define SYSCALL_TABLE_H__

#include <sys/types.h>
#include "trusted_thread.h"

struct syscall_handler {
  // handler executes when the application make a request for a system call
  void     (*handler_request_untrusted)(syscall_request *, const ucontext_t *); 
  // handler executed by the untrudted thread when it receives the result of system call
  void     (*handler_result_untrusted)( const syscall_request *); 
  //handler executed by the trusted thread when it receives a request 
  void     (*handler_trusted)( const syscall_request *); 
};

/* INTERFACE */
extern struct syscall_handler * syscall_table;
void initialize_syscall_table();  

#endif // SYSCALL_TABLE_H__
