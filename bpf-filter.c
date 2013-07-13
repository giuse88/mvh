#include "common.h"
#include "bpf-filter.h"
#include "trusted_thread.h"
#include <signal.h>
#include <unistd.h> 
#include <stdlib.h> 
#include <stdio.h> 
#include <string.h>
#include <ucontext.h> 
#include "x86_decoder.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "library.h" 
#include "sandbox.h"
#include "tls.h"

#include "syscall_x64.h"

#include <sys/syscall.h>

#define __USE_GNU 1
#define _GNU_SOURCE 1



int  find_function_boundaries( char * instr, char **start, char ** end ) 
{

   char * ptr=instr;

   for (unsigned short i; *ptr != '\xC3'; )
      i=next_inst((const char **)&ptr, true,0, 0, 0, 0, 0);
    
   *end=ptr; 

   ptr=instr;

   for (int nopcount=0; nopcount < 2 ; ptr--)
       if(*ptr == '\x90')
           nopcount++; 
       else 
           nopcount=0;

   *start=ptr; 

   return SUCCESS;
}


void emulator(int nr, siginfo_t  *info, void *void_context)
{
  ucontext_t *ctx = (ucontext_t *)(void_context);
  register_size _syscall,pc, stack_base, stack; 
  syscall_request syscall_request; 
  syscall_result syscall_result; 
  /*char *start=NULL, *end=NULL; */


  if (info->si_code != SYS_SECCOMP)
    return;
  
  if (!ctx) 
    return;

  _syscall = ctx->uc_mcontext.gregs[REG_SYSCALL];
/*  pc=ctx->uc_mcontext.gregs[REG_PC];*/
  /*stack=ctx->uc_mcontext.gregs[REG_STACK];*/
  /*stack_base=ctx->uc_mcontext.gregs[REG_BASE];*/

  pid_t tid= (pid_t)get_local_tid(); 
  /*// Note  si_call_addr points to the instruction after the syscall instruction */
  DPRINT(DEBUG_INFO, "== [%d] Start emulation of %s \n", tid ,syscall_names[_syscall]);
  DPRINT(DEBUG_INFO, "Syscall instruction address %p\n", info->si_call_addr);

  // let assume that the boundaries are correct 
/*  find_function_boundaries((char *)info->si_call_addr, &start, &end); */
  /*DPRINT(DEBUG_INFO, "Function start %p end %p \n",start, end);*/

  //  disable the patch mechanism 
  /*patch_syscalls_in_func(start, end);*/
 
  fill_syscall_request(ctx, &syscall_request); 

  if(send_syscall_request(&syscall_request) < 0 )
     die("Failed to send system call request"); 

  if(get_syscall_result(&syscall_result) < 0) 
     die("Failed to receive the syscall result"); 

  ctx->uc_mcontext.gregs[REG_RESULT] = syscall_result.result;

  DPRINT(DEBUG_INFO, "== [%d] End emulation of %s\n", tid,syscall_names[_syscall]);

  return;
}


 int install_filter(int fd)
{
  struct sock_filter f[] = 
  {
    VALIDATE_ARCHITECTURE,
    EXAMINE_SYSCALL,
    ALLOW_SYSCALL(rt_sigreturn),
    ALLOW_SYSCALL(rt_sigprocmask),
    ALLOW_ARGUMENT(write, 0, fd),
    ALLOW_ARGUMENT(read, 0, fd),
#ifdef DEBUG
    ALLOW_ARGUMENT(write , 0, STDERR_FILENO),
#endif
    TRAP_PROCESS, 
    KILL_PROCESS,
 };

  struct sock_fprog prog = 
  {
		.len = (unsigned short)(sizeof(f)/sizeof(f[0])),
		.filter = f,
  };

  // I need to allow read and write 
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) 
		die("prctl(NO_NEW_PRIVS)");

  DPRINT(DEBUG_INFO, "Released priviledge\n"); 

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
		perror("prctl(BPF FILTER)"); 

  DPRINT(DEBUG_INFO, "In seccomp BPF mode\n"); 

  return SUCCESS;
} 
