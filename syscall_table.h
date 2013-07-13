#ifndef SYSCALL_TABLE_H__
#define SYSCALL_TABLE_H__

#include <sys/types.h>
#include "trusted_thread.h"

#define NO_HANDLER (void*)NULL 

struct syscall_handler {
  void     (*handler)(syscall_request *, const ucontext_t *); 
};

/* INTERFACE */
extern struct syscall_handler * syscall_table;
void initialize_syscall_table();  

#endif // SYSCALL_TABLE_H__
