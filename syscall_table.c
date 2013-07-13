#include "syscall_table.h"
#include <asm/unistd.h>
#include <sys/mman.h>
#include "common.h"
#include "tls.h" 

#if defined (__i386__)
  #define MAX_SYSTEM_CALL 445 
#elif  defined (__x86_64__)
  #define MAX_SYSTEM_CALL 312  
#else 
  #error Architecture not supported
#endif

int __test=1234; 
struct syscall_handler * syscall_table;

size_t get_syscall_table_size() 
{
  return ((sizeof(struct syscall_handler) * (MAX_SYSTEM_CALL + 1)) + 4095) & ~4095;
}

void protect_syscall_table()
{
  if (mprotect(syscall_table,get_syscall_table_size(), PROT_READ) != 0) 
     die("Failed to protect system call table");
}

void unprotect_syscall_table()
{
    if (mprotect(syscall_table, get_syscall_table_size(),PROT_READ | PROT_WRITE) != 0)
       die("Failed to unprotect system call table");
}

/* HANDLERS */ 
void sys_open  (syscall_request * req, const ucontext_t * context )
{
   /*open ( char * "path", mode ) */ 
//   DPRINT(DEBUG_INFO, " --OPEN-- System call handler\n");
   req->has_indirect_arguments=true; 
   req->indirect_arguments=1;
   req->args[0].content= (char *)req->arg0; 
   req->args[0].size = strlen((char *)req->arg0) + 1; 
   req->args[0].argument_number = 0;
}

void sys_write (syscall_request * req , const ucontext_t * context )
{
   req->has_indirect_arguments=true; 
   req->indirect_arguments=1;
   req->args[0].content= (char *)req->arg1; 
   req->args[0].size = req->arg2 ; 
   req->args[0].argument_number = 1;
}

void sys_read (syscall_request * req, const ucontext_t * context ){
   /*open ( char * "path", mode ) */ 
 //  DPRINT(DEBUG_INFO, " --READ-- System call handler\n");
   req->has_indirect_arguments=true; 
   req->indirect_arguments=1;
   req->args[0].content= (char *)req->arg1; 
   req->args[0].size = req->arg2 ; 
   req->args[0].argument_number = 1;
}

void sys_clone ( syscall_request *req , const ucontext_t * context) {

   DPRINT(DEBUG_INFO, " --CLONE-- System call handler\n");

   char *stack = (char *)req->arg1; 
   char *child_stack=stack; 
   void *dummy;
   
   asm volatile( "mov %%rsp, %%rcx\n"
                 "mov %3, %%rsp\n"
                 "int $0\n"
                 "mov %%rcx, %%rsp\n"
                 : "=a"(stack), "=&c"(dummy)
                 : "a"(__NR_clone + 0xF000), "m"(stack)
                 : "memory");
 
   req->arg1=(long)stack;
   ucontext_t * uc = (struct ucontext *)stack;
   // copy state and signal mask of the untrusted process 
   memcpy(uc, context, sizeof(struct ucontext)); 
   uc->uc_mcontext.gregs[REG_RESULT]=0; 
   uc->uc_mcontext.gregs[REG_RSP]=(long)child_stack; 
   
}
/* Initialize Routine */ 
void initialize_syscall_table() 
{

  static const struct policy {
    unsigned syscallNum;
    void     (*handler)( syscall_request *, const ucontext_t *  );  
  } default_policy[] = {
    { __NR_exit,        NO_HANDLER },
    { __NR_exit_group,  NO_HANDLER },
    { __NR_clone ,      sys_clone }, 
    { __NR_open ,       sys_open },
    { __NR_write,       sys_write },
    { __NR_read,        sys_read },
  };
 
  if (syscall_table) 
        return;  

  syscall_table = (struct syscall_handler*)(
    mmap(NULL, get_syscall_table_size(),
         PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0));

  if (syscall_table == MAP_FAILED) 
     die("Failed to allocate system call table");
 
   /*fill in the system call table*/
  for (const struct policy *policy = default_policy;
       policy-default_policy < (int)(sizeof(default_policy)/sizeof(struct policy));
       ++policy) 
           syscall_table[policy->syscallNum].handler        = policy->handler;
      
  protect_syscall_table(); 
}
