#include "syscall_table.h"
#include <asm/unistd.h>
#include <sys/mman.h>
#include "common.h"
#include "tls.h" 
#include "handler.h" 
#include "sandbox.h" 

#if  defined (__x86_64__)
  #define MAX_SYSTEM_CALL 312  
#else 
  #error Architecture not supported
#endif

// SYSTEM CALL TABLE ( GLOBAL)
struct syscall_handler * syscall_table_;

size_t get_syscall_table_size() {
  return ((sizeof(struct syscall_handler) * (MAX_SYSTEM_CALL + 1)) + 4095) & ~4095;
}
void protect_syscall_table(){
  if (mprotect(syscall_table_,get_syscall_table_size(), PROT_READ) != 0) 
     die("Failed to protect system call table");
}
void unprotect_syscall_table(){
    if (mprotect(syscall_table_, get_syscall_table_size(),PROT_READ | PROT_WRITE) != 0)
       die("Failed to unprotect system call table");
}

/* Initialize Routine */ 
void initialize_syscall_table() 
{
  if (syscall_table_) 
        return;  
 
  // a bit ugly but i don t want to expose the 
  // system call handler in the global memory without 
  // any memory protection mechanism
 #include "policy.h"  
 
  const struct policy* default_policy=
      (sandbox.visibility == PUBLIC) ? public_policy : private_policy; 
 // they should be equal  
  int size =  (sandbox.visibility == PUBLIC)? sizeof(public_policy) : sizeof(public_policy); 

  syscall_table_ = (struct syscall_handler*)(
    mmap(NULL, get_syscall_table_size(),
         PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0));

  if (syscall_table_ == MAP_FAILED) 
     die("Failed to allocate system call table");

   // default 
  for (struct syscall_handler * sys_han = syscall_table_; 
        sys_han < syscall_table_ + MAX_SYSTEM_CALL; sys_han++) {
    sys_han->handler_trusted = DEFAULT_TRUSTED;
    sys_han->handler_untrusted = DEFAULT_UNTRUSTED;
  }

   /*fill out the system call table*/
  for (const struct policy *policy = default_policy;
       policy-default_policy < (int)(size/sizeof(struct policy));
       ++policy) {
           syscall_table_[policy->syscallNum].handler_untrusted  = policy->handler_untrusted;
           syscall_table_[policy->syscallNum].handler_trusted    = policy->handler_trusted;
  }

  protect_syscall_table();
  DPRINT(DEBUG_INFO, "Loaded system call table\n");  

}
