#ifndef TRUSTED_THREAD_H
#define TRUSTED_THREAD_H

#include "bpf-filter.h"
#include <stdbool.h>
#include "abstract_data/list.h" 

typedef unsigned long register_size;

#define MAX_ARGS 1

struct indirect_argument
{
    char * content; 
    size_t size;
    unsigned argument_number;
}; 


typedef enum {UNTRUSTED_THREAD, TRUSTED_THREAD} thread_type;

typedef struct __attribute__((packed))
{
   register_size syscall_identifier; 
   register_size arg0; 
   register_size arg1; 
   register_size arg2; 
   register_size arg3; 
   register_size arg4; 
   register_size arg5; 
   int cookie; 
   bool ignore;
   bool has_indirect_arguments; 
   int  indirect_arguments;
   struct indirect_argument args[MAX_ARGS]; 
} syscall_request; 

typedef struct __attribute__((packed)) 
{
    register_size result;
    int cookie; 
} syscall_result;

struct thread_info
{
  pid_t pid;
  pid_t tid;
  pid_t sid; 
  pid_t gid; 
  // This field is significant only if the thread is trusted 
  // if so it contains the thread id of the untrusted thread 
  // associated with this thread 
  pid_t monitored_thread_id;     
  // the type of the thread (trusted, untrusted) 
  thread_type type; 
  int cookie; 
}__attribute__((packed)); 

struct ThreadArgs 
{
      pid_t untrusted_thread_tid; 
}__attribute__ ((aligned(16)));

struct thread_local_info
{ 
    pid_t my_tid; 
    pid_t monitored_thread_id;
    int fd_remote_process;
    
}__attribute__((packed)); 

struct untrusted_thread_list {
    struct thread_local_info info; 
    struct list_head list;
}; 

extern int  create_trusted_thread(); 
extern void print_syscall_info(const syscall_request * ); 
extern void fill_syscall_request(
                                  const ucontext_t * context,  syscall_request * request); 
extern int  send_syscall_request( 
                                  const syscall_request * req); 
extern int  get_syscall_result (  
                                  syscall_result * res); 

#endif /* end of include guard: TRUSTED_THREAD_H */
