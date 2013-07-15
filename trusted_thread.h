#ifndef TRUSTED_THREAD_H
#define TRUSTED_THREAD_H

#include "bpf-filter.h"
#include <stdbool.h>
#include "abstract_data/list.h" 
#include "sandbox.h" 


typedef enum {UNTRUSTED_THREAD, TRUSTED_THREAD} thread_type;
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
  // I need to know if the thread is public or provate 
  process_visibility visibility; 
  // cookie whihc identifies the pair trusted and untrusted 
  int cookie;
}__attribute__((packed)); 

#define SIZE_THREAD_INFO sizeof(struct thread_info)

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

#endif /* end of include guard: TRUSTED_THREAD_H */
