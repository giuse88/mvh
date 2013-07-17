#include "bpf-filter.h"
#include "trusted_thread.h"
#include <signal.h>
#include <unistd.h> 
#include <stdlib.h> 
#include <stdio.h> 
#include <string.h>
#include "x86_decoder.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "library.h" 
#include "sandbox.h"
#include "tls.h"
#include "syscall_x64.h"
#include <sys/syscall.h>
#include "common.h"
#include "syscall_table.h" 

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
  u64_t syscallNum; 
  pid_t tid= (pid_t)get_local_tid(); 
  
  if (info->si_code != SYS_SECCOMP)
    return;
  
  if (!ctx) 
    return;

  syscallNum = ctx->uc_mcontext.gregs[REG_SYSCALL];

  /*// Note  si_call_addr points to the instruction after the syscall instruction */
  DPRINT(DEBUG_INFO, "== [%d] Start emulation of %s \n", tid ,syscall_names[syscallNum]);

  ctx->uc_mcontext.gregs[REG_RESULT] = syscall_table_[syscallNum].handler_untrusted(ctx);

  DPRINT(DEBUG_INFO, "== [%d] End emulation of %s\n", tid,syscall_names[syscallNum]);
  return;
}
int install_filter(int fd){
  struct sock_filter f[] = 
  {
    VALIDATE_ARCHITECTURE,
    EXAMINE_SYSCALL,
    ALLOW_SYSCALL(rt_sigreturn),
    ALLOW_ARGUMENT(write, 0, fd),
    ALLOW_ARGUMENT(read, 0, fd),
    ALLOW_ARGUMENT(sendmsg, 0, fd),
    ALLOW_ARGUMENT(recvmsg, 0, fd),
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
