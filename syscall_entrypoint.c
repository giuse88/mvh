#include "syscall_entrypoint.h"
#include "trusted_thread.h"
#include "handler.h" 
#include <signal.h>
#include <unistd.h> 
#include "x86_decoder.h"
#include "syscall_table.h"
#include "tls.h" 


asm(
    ".pushsection .text, \"ax\", @progbits\n"

#if defined(__x86_64__)
   "syscall_enter_without_frame:"
    ".internal syscall_enter_without_frame\n"
    ".globl syscall_enter_without_frame\n"
    ".type syscall_enter_without_frame, @function\n"
    "mov  0(%rsp), %r11\n"         // add fake return address by duplicating
    "push %r11\n"                  // real return address

    ".size syscall_enter_without_frame, .-syscall_enter_without_frame\n"

    "syscall_enter_with_frame:"
    ".internal syscall_enter_with_frame\n"
    ".globl syscall_enter_with_frame\n"
    ".type syscall_enter_with_frame, @function\n"
    // Save all registers
  "1:push %rbp\n"
    "movq  $0xDEADBEEFDEADBEEF, %rbp\n" // marker used by breakpad to remove
    "push %rbp\n"                  // seccomp-sandbox's stack frame from dumps
    "mov  %rsp, %rbp\n"
    "push %rbx\n"
    "push %rcx\n"
    "push %rdx\n"
    "push %rsi\n"
    "push %rdi\n"
    "push %r8\n"
    "push %r9\n"
    "push %r10\n"
    "push %r11\n"
    "push %r12\n"
    "push %r13\n"
    "push %r14\n"
    "push %r15\n"

    // translation from syscall calling covention
    // to function calling convention 

    "push %rax\n"
     
    "call pad_request\n" 

    // cleaning the stack 
    "add $8, %rsp\n" 

    // Restore CPU registers, except for %rax which was set by the system call.
    "pop %r15\n"
    "pop %r14\n"
    "pop %r13\n"
    "pop %r12\n"
    "pop %r11\n"
    "pop %r10\n"
    "pop %r9\n"
    "pop %r8\n"
    "pop %rdi\n"
    "pop %rsi\n"
    "pop %rdx\n"
    "pop %rcx\n"
    "pop %rbx\n"
    "pop %rbp\n"                   // 0xDEADBEEF marker
    "pop %rbp\n"

    // Remove fake return address. This is added in the patching code in
    // library.cc and it makes stack traces a little cleaner.
    "add $8, %rsp\n"

    // Return to caller
    "ret\n"

#else
#error Unsupported target platform
#endif
    ".size syscall_enter_with_frame, .-syscall_enter_with_frame\n"
    ".popsection\n"
);


int  pad_request( unsigned long arg1, 
                  unsigned long arg2, 
                  unsigned long arg3, 
                  unsigned long arg4, 
                  unsigned long arg5, 
                  unsigned long arg6, 
                  unsigned long sysnum)  __attribute__ ((visibility ("internal"))); 


int pad_request( unsigned long arg0, 
                  unsigned long arg1, 
                  unsigned long arg2,  
                  unsigned long arg3, 
                  unsigned long arg4, 
                  unsigned long arg5,
                  unsigned long sysnum)
{

   ucontext_t uc; 
   u64_t result; 
   pid_t tid= (pid_t)get_local_tid(); 

   memset((void*)&uc, 0, sizeof(uc)); 
   
   uc.uc_mcontext.gregs[REG_SYSCALL] = sysnum; 
   uc.uc_mcontext.gregs[REG_ARG0] = arg0;  
   uc.uc_mcontext.gregs[REG_ARG1] = arg1; 
   uc.uc_mcontext.gregs[REG_ARG2] = arg2; 
   uc.uc_mcontext.gregs[REG_ARG3] = arg3;  
   uc.uc_mcontext.gregs[REG_ARG4] = arg4;
   uc.uc_mcontext.gregs[REG_ARG5] = arg5; 

   DPRINT(DEBUG_INFO, "== [%d] Start emulation of %s via (JUMP)\n", tid ,syscall_names[sysnum]);
  
   result = syscall_table_[sysnum].handler_untrusted(&uc); 
 
   DPRINT(DEBUG_INFO, "== [%d] End emulation of %s via (JUMP)\n\n", tid,syscall_names[sysnum]);
 
   return result; 

}
