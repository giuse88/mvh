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

   "syscall_enter_without_frame:"
    ".internal syscall_enter_without_frame\n"
    ".globl syscall_enter_without_frame\n"
    ".type syscall_enter_without_frame, @function\n"
#if defined(__x86_64__)
    "mov  0(%rsp), %r11\n"         // add fake return address by duplicating
    "push %r11\n"                  // real return address
    /* fall through */
#else
  #error Unsupported target platform
#endif

    ".size syscall_enter_without_frame, .-syscall_enter_without_frame\n"

    "syscall_enter_with_frame:"
    ".internal syscall_enter_with_frame\n"
    ".globl syscall_enter_with_frame\n"
    ".type syscall_enter_with_frame, @function\n"
#if defined(__x86_64__)
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


    // This code is only x86_64 compatible 

    // translation from syscall calling covention
    // to function calling convention 

    // 7th argmument in the stack  
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



  /*"3:"*/
    /*// If we end up calling a specific handler, we don't need to know the*/
    /*// system call number. However, in the generic case, we do. Shift*/
    /*// registers so that the system call number becomes visible as the first*/
    /*// function argument.*/
    /*"push %r9\n"*/
    /*"mov  %r8, %r9\n"*/
    /*"mov  %r10, %r8\n"*/
    /*"mov  %rdx, %rcx\n"*/
    /*"mov  %rsi, %rdx\n"*/
    /*"mov  %rdi, %rsi\n"*/
    /*"mov  %rax, %rdi\n"*/

    /*// Call default handler*/
    /*"call syscall_default_handler\n"*/
    /*"pop  %r9\n"*/
    /*"jmp 2b\n"*/
/*#elif defined(__i386__)*/
    /*"cmp  $119, %eax\n"            // NR_sigreturn*/
    /*"jnz  1f\n"*/
    /*"add  $0x8, %esp\n"            // pop return address*/
  /*"0:int  $0x80\n"                 // sigreturn() is unrestricted*/
    /*"mov  $66, %ebx\n"             // sigreturn() should never return*/
    /*"mov  %ebx, %eax\n"            // NR_exit*/
    /*"jmp  0b\n"*/
  /*"1:cmp  $173, %eax\n"            // NR_rt_sigreturn*/
    /*"jnz  4f\n"*/

    /*// Convert rt_sigframe into sigframe, allowing us to call sigreturn().*/
    /*// This is possible since the first part of signal stack frames have*/
    /*// stayed very stable since the earliest kernel versions. While never*/
    /*// officially documented, lots of user space applications rely on this*/
    /*// part of the ABI, and kernel developers have been careful to maintain*/
    /*// backwards compatibility.*/
    /*// In general, the rt_sigframe includes a lot of extra information that*/
    /*// the signal handler can look at. Most notably, this means a complete*/
    /*// siginfo record.*/
    /*// Fortunately though, the kernel doesn't look at any of this extra data*/
    /*// when returning from a signal handler. So, we can safely convert an*/
    /*// rt_sigframe to a legacy sigframe, discarding the extra data in the*/
    /*// process. Interestingly, the legacy signal frame is actually larger than*/
    /*// the rt signal frame, as it includes a lot more padding.*/
    /*"sub  $0x1C4, %esp\n"          // a legacy signal stack is much larger*/
    /*"mov  0x1CC(%esp), %eax\n"     // push signal number*/
    /*"push %eax\n"*/
    /*"lea  0x270(%esp), %esi\n"     // copy siginfo register values*/
    /*"lea  0x4(%esp), %edi\n"       //     into new location*/
    /*"mov  $0x16, %ecx\n"*/
    /*"cld\n"*/
    /*"rep movsl\n"*/
    /*"mov  0x2C8(%esp), %ebx\n"     // copy first half of signal mask*/
    /*"mov  %ebx, 0x54(%esp)\n"*/
    /*"call 2f\n"*/
  /*"2:pop  %esi\n"*/
    /*"add  $(3f-2b), %esi\n"*/
    /*"push %esi\n"                  // push restorer function*/
    /*"lea  0x2D4(%esp), %edi\n"     // patch up retcode magic numbers*/
    /*"movb $2, %cl\n"*/
    /*"rep movsl\n"*/
    /*"ret\n"                        // return to restorer function*/
  /*"3:pop  %eax\n"                  // remove dummy argument (signo)*/
    /*"mov  $119, %eax\n"            // NR_sigaction*/
    /*"int  $0x80\n"*/


    /*// Preserve all registers*/
  /*"4:push %ebp\n"*/
    /*"push $0xDEADBEEF\n"           // marker used by breakpad*/
    /*"push %ebx\n"*/
    /*"push %ecx\n"*/
    /*"push %edx\n"*/
    /*"push %esi\n"*/
    /*"push %edi\n"*/

    /*// Align stack pointer, so that called functions can push SSE registers*/
    /*// onto stack. This apparently is a requirement of the x86-32 ABI.*/
    /*"mov  %esp, %ebp\n"*/
    /*"and  $-16, %esp\n"*/
    /*"sub $4, %esp\n"*/
    /*"push %ebp\n"                  // push old un-aligned stack pointer*/
    /*"lea  0x14(%ebp), %ebp\n"      // frame pointer points to 0xDEADBEEF*/
    /*"push %eax\n"*/
    /*"mov  4(%ebp), %eax\n"         // push original value of %ebp*/
    /*"xchg %eax, 0(%esp)\n"*/

    /*// Convert from syscall calling conventions to C calling conventions*/
    /*"push %edi\n"*/
    /*"push %esi\n"*/
    /*"push %edx\n"*/
    /*"push %ecx\n"*/
    /*"push %ebx\n"*/
    /*"push %eax\n"*/

    /*// Check range of system call*/
    /*"call 5f\n"*/
  /*"5:pop  %edx\n"*/
    /*"add $(_GLOBAL_OFFSET_TABLE_+(.-5b)), %edx\n"*/
    /*"mov syscall_table_size@GOT(%edx), %edx\n"*/
    /*"cmp 0(%edx), %eax\n"*/
    /*"ja  14f\n"*/

    /*// We often have long sequences of calls to gettimeofday(). This is*/
    /*// needlessly expensive. Coalesce them into a single call.*/
    /*//*/
    /*// We keep track of state in TLS storage that we can access through the*/
    /*// %fs segment register. See trusted_thread.cc for the exact memory*/
    /*// layout.*/
    /*//*/
    /*// TODO(markus): maybe, we should proactively call gettimeofday() and*/
    /*//               clock_gettime(), whenever we talk to the trusted thread?*/
    /*//               or maybe, if we have recently seen requests to compute*/
    /*//               the time. There might be a repeated pattern of those.*/
    /*"cmp  $78, %eax\n"             // __NR_gettimeofday*/
    /*"jnz  10f\n"*/
    /*"cmp  %eax, %fs:0x102C-0x58\n" // last system call*/
    /*"jnz  7f\n"*/

    /*// This system call and the last system call prior to this one both are*/
    /*// calls to gettimeofday(). Try to avoid making the new call and just*/
    /*// return the same result as in the previous call.  Just in case the*/
    /*// caller is spinning on the result from gettimeofday(), every so often,*/
    /*// call the actual system call.*/
    /*"decl %fs:0x1030-0x58\n"       // countdown calls to gettimofday()*/
    /*"jz   7f\n"*/

    /*// Atomically read the 64bit word representing last-known timestamp and*/
    /*// return it to the caller. On x86-32 this is a little more complicated*/
    /*// and requires the use of the cmpxchg8b instruction.*/
    /*"mov  %ebx, %eax\n"*/
    /*"mov  %ecx, %edx\n"*/
    /*"call 6f\n"*/
  /*"6:pop %ebp\n"*/
    /*"add $(100f-6b), %ebp\n"*/
    /*"lock; cmpxchg8b 0(%ebp)\n"*/
    /*"mov  %eax, 0(%ebx)\n"*/
    /*"mov  %edx, 4(%ebx)\n"*/
    /*"xor  %eax, %eax\n"*/
    /*"add  $28, %esp\n"*/
    /*"jmp  13f\n"*/

    /*// This is a call to gettimeofday(), but we don't have a valid cached*/
    /*// result, yet.*/
  /*"7:mov  %eax, %fs:0x102C-0x58\n" // remember syscall number*/
    /*"movl $500, %fs:0x1030-0x58\n" // make system call, each 500 invocations*/
    /*"call syscall_default_handler@PLT\n"*/

    /*// Returned from gettimeofday(). Remember return value, in case the*/
    /*// application calls us again right away.*/
    /*// Again, this has to happen atomically and requires cmpxchg8b.*/
    /*"mov 4(%ebx), %ecx\n"*/
    /*"mov 0(%ebx), %ebx\n"*/
    /*"call 8f\n"*/
  /*"8:pop %ebp\n"*/
    /*"add $(100f-8b), %ebp\n"*/
    /*"mov 0(%ebp), %eax\n"*/
    /*"mov 4(%ebp), %edx\n"*/
  /*"9:lock; cmpxchg8b 0(%ebp)\n"*/
    /*"jnz 9b\n"*/
    /*"xor %eax, %eax\n"*/
    /*"jmp 15f\n"*/

    /*// Remember the number of the last system call made. We deliberately do*/
    /*// not remember calls to gettid(), as we have often seen long sequences of*/
    /*// calls to just gettimeofday() and gettid(). In that situation, we would*/
    /*// still like to coalesce the gettimeofday() calls.*/
 /*"10:cmp $224, %eax\n"             // __NR_gettid*/
    /*"jz  11f\n"*/
    /*"mov  %eax, %fs:0x102C-0x58\n" // remember syscall number*/

    /*// Retrieve function call from system call table (c.f.syscall_table.c)*/
    /*// We have three different types of entries; zero for denied system calls,*/
    /*// that should be handled by the default_syscall_handler(); minus one*/
    /*// for unrestricted system calls that need to be forwarded to the trusted*/
    /*// thread; and function pointers to specific handler functions.*/
 /*"11:shl  $3, %eax\n"*/
    /*"call 12f\n"*/
 /*"12:pop  %ebx\n"*/
    /*"add  $(_GLOBAL_OFFSET_TABLE_+(.-12b)), %ebx\n"*/
    /*"mov  syscall_table_@GOT(%ebx), %ebx\n"*/
    /*"add  0(%ebx), %eax\n"*/
    /*"mov  0(%eax), %eax\n"*/

    /*// Jump to function if non-null and not UNRESTRICTED_SYSCALL, otherwise*/
    /*// jump to fallback handler.*/
    /*"cmp  $1, %eax\n"*/
    /*"jbe  14f\n"*/
    /*"add  $4, %esp\n"*/
    /*"call *%eax\n"*/
    /*"add  $24, %esp\n"*/

    /*// Restore CPU registers, except for %eax which was set by the system call.*/
 /*"13:pop  %esp\n"*/
    /*"pop  %edi\n"*/
    /*"pop  %esi\n"*/
    /*"pop  %edx\n"*/
    /*"pop  %ecx\n"*/
    /*"pop  %ebx\n"*/
    /*"pop  %ebp\n"                  // 0xDEADBEEF marker*/
    /*"pop  %ebp\n"*/

    /*// Remove fake return address. This is added in the patching code in*/
    /*// library.cc and it makes stack traces a little cleaner.*/
    /*"add  $4, %esp\n"*/

    /*// Return to the caller*/
    /*"ret\n"*/

    /*// Call the default handler*/
 /*"14:call syscall_default_handler@PLT\n"*/
 /*"15:add  $28, %esp\n"*/
    /*"jmp  13b\n"*/

    /*".pushsection \".bss\"\n"*/
    /*".balign 8\n"*/
/*"100:.byte 0, 0, 0, 0, 0, 0, 0, 0\n"*/
    /*".popsection\n"*/

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

// Easy function that pads a request structure to send to the trusted thread; 
int pad_request( unsigned long arg0, 
                  unsigned long arg1, 
                  unsigned long arg2,  
                  unsigned long arg3, 
                  unsigned long arg4, 
                  unsigned long arg5,
                  unsigned long sysnum)
{

   ucontext_t uc; 
   int result; 
   pid_t tid= (pid_t)get_local_tid(); 

   memset((void*)&uc, 0, sizeof(uc)); 
   
   uc.uc_mcontext.gregs[REG_SYSCALL] = sysnum; 
   uc.uc_mcontext.gregs[REG_ARG0] = arg0;  
   uc.uc_mcontext.gregs[REG_ARG1] = arg1; 
   uc.uc_mcontext.gregs[REG_ARG2] = arg2; 
   uc.uc_mcontext.gregs[REG_ARG3] = arg3;  
   uc.uc_mcontext.gregs[REG_ARG4] = arg4;
   uc.uc_mcontext.gregs[REG_ARG5] = arg5; 

   DPRINT(DEBUG_INFO, "== [%d] Start emulation of %s \n", tid ,syscall_names[sysnum]);
  
   result = syscall_table_[sysnum].handler_untrusted(&uc); 
 
   DPRINT(DEBUG_INFO, "== [%d] End emulation of %s\n\n", tid,syscall_names[sysnum]);
 
   return result; 

}

/*#include "syscall_names.h"*/

/*void *syscall_default_handler(int sysno, void *arg0, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5) {*/
  /*// TODO: The following comment is currently not true, we do intercept these system calls. Try to fix that.*/

  /*// We try to avoid intercepting mmap(), and munamp(), ... as these system*/
  /*// calls are not restricted. But depending on the exact instruction sequence*/
  /*// in libc, we might not be able to reliably filter out these system calls*/
  /*// at the time when we instrument the code.*/
  /*long ret;*/
  /*//long long tm;*/

  /*const char __attribute__((unused)) *sysname = syscall_names[sysno];*/
  /*sys_write(2, sysname, strlen(sysname));*/
  /*sys_write(2, "\n", 1);*/

  /*switch (sysno) {*/
  /*case __NR_mmap:*/
    /*//DPRINTF(DLVL_INFO, "Allowing unrestricted system call\n");*/
    /*ret = (long) sys_mmap(arg0, (size_t) arg1, (intptr_t) arg2, (intptr_t) arg3, (intptr_t) arg4, (off_t) arg5);*/
    /*break;*/
  /*case __NR_mprotect:*/
    /*ret = sys_mprotect(arg0, (size_t) arg1, (intptr_t) arg2);*/
    /*break;*/
  /*case __NR_munmap:*/
    /*ret = sys_munmap(arg0, (size_t) arg1);*/
    /*break;*/
  /*case __NR_brk:*/
    /*ret = (long) sys_brk(arg0);*/
    /*break;*/
  /*default:*/
    /*ret = __syscall(sysno, arg0, arg1, arg2, arg3, arg4, arg5);*/
    /*return (void *)ret;*/
/*#ifdef DEBUG*/
    /*// Prevent stderr from being closed in debug mode*/
    /*if (sysno == __NR_close && arg0 == (void *)2)*/
      /*return 0;*/
/*#endif*/

    /*//if ((unsigned int)sysno > syscall_table_size || !syscall_table[sysno].handler)*/
    /*//  return (void *)-ENOSYS;*/

    /*//struct {*/
    /*//  int sysno;*/
    /*//  void *args[6];*/
    /*//} __attribute__((packed)) req = { sysno, { arg0, arg1, arg2, arg3, arg4, arg5 } };*/

    /*//int thread = thread_fd_pub();*/
    /*//void *ret;*/
    /*//if (__write(thread, &req, sizeof(req)) != sizeof(req) ||*/
    /*//    __read(thread, &ret, sizeof(ret)) != sizeof(ret)) {*/
    /*//  die("Failed to forward unrestricted system call");*/
    /*//}*/
    /*//return (void *)ret;*/
  /*}*/
  /*if (ret < 0) {*/
    /*ret = -errno;*/
  /*}*/
  /*return (void *)ret;*/
/*}*/
