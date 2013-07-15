#include "handler.h"
#include "common.h"
#include "tls.h"
#include "sandbox.h"
#include "bpf-filter.h"
#include "trusted_thread.h"

#include <sys/mman.h> 
#include <sys/syscall.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/syscall.h>

int send_syscall_request(const syscall_request * req) {
   int sent; 
   int fd = get_local_fd(); 

   INTR_RES(write( fd,(char *)req, sizeof(syscall_request)), sent); 

    if (req->has_indirect_arguments) 
      for (int i=0; i< req->indirect_arguments; i++)
          INTR_RES(write(fd,
                      (char *)req->args[i].content,req->args[i].size), sent);     
    return sent; 
}
int get_syscall_result (syscall_result * res){
    int received;
    int fd = get_local_fd(); 
    pid_t tid = get_local_tid(); 

    INTR_RES(read(fd, (char *)res, sizeof(syscall_result)), received); 

    if (res->cookie != tid)
        die("cookie verification failed (result)"); 

    return received; 
}

/**********************************************************************
 *                          DEFAULT                                   *
 **********************************************************************/
u64_t untrusted_default(const ucontext_t *ctx ){
   
    int syscallNum = -1; 
    syscall_result result; 
    syscall_request request; 
  
    syscallNum = ctx->uc_mcontext.gregs[REG_SYSCALL];
    DPRINT(DEBUG_INFO, "Start DEFAULT handler for < %s > \n", syscall_names[syscallNum]);

    memset((void*)&request, 0, sizeof(syscall_request)); 
    memset((void*)&result,  0, sizeof(syscall_result)); 
 
   request.syscall_identifier = ctx->uc_mcontext.gregs[REG_SYSCALL]; 
   request.arg0 = ctx->uc_mcontext.gregs[REG_ARG0]; 
   request.arg1 = ctx->uc_mcontext.gregs[REG_ARG1]; 
   request.arg2 = ctx->uc_mcontext.gregs[REG_ARG2]; 
   request.arg3 = ctx->uc_mcontext.gregs[REG_ARG3]; 
   request.arg4 = ctx->uc_mcontext.gregs[REG_ARG4];
   request.arg5 = ctx->uc_mcontext.gregs[REG_ARG5]; 
   request.cookie = get_local_tid();  

   if(send_syscall_request(&request) < 0)
       die("Error sending system call request"); 

   if(get_syscall_result(&result) < 0 )
       die("Failede get_syscall_result"); 

   DPRINT(DEBUG_INFO, " End DEFAULT handler for < %s > \n", syscall_names[syscallNum]);
   return (u64_t)result.result; 
}
void trusted_default (const syscall_request *request, int fd){

  syscall_result result; 
  int nwrite=-1; 

  memset(&result, 0, sizeof(result)); 

  DPRINT(DEBUG_INFO, "Start DEFAULT trusted thread for system call < %s > \n",
            syscall_names[request->syscall_identifier]);
    
  result.result = do_syscall(request);
  result.cookie = request->cookie; 

  INTR_RES(write(fd,(char *)&result,sizeof(result)), nwrite); 

  if (nwrite < (int)sizeof(result)) 
        die("Failed write system call arguments"); 

  DPRINT(DEBUG_INFO, "End DEFAULT trusted thread for system call < %s > \n",
            syscall_names[request->syscall_identifier]);
 
}


//open 
void open_untrusted(syscall_request *req, const ucontext_t * uc ){
  DPRINT(DEBUG_INFO, "Open request\n");
/*void sys_open  (syscall_request * req, const ucontext_t * context )*/
/*{*/
   /*[>open ( char * "path", mode ) <] */
/*//   DPRINT(DEBUG_INFO, " --OPEN-- System call handler\n");*/
   /*req->has_indirect_arguments=true; */
   /*req->indirect_arguments=1;*/
   /*req->args[0].content= (char *)req->arg0; */
   /*req->args[0].size = strlen((char *)req->arg0) + 1; */
   /*req->args[0].argument_number = 0;*/
/*}*/


} 
/*
void sys_write (syscall_request * req , const ucontext_t * context )
{
   req->has_indirect_arguments=true; 
   req->indirect_arguments=1;
   req->args[0].content= (char *)req->arg1; 
   req->args[0].size = req->arg2 ; 
   req->args[0].argument_number = 1;
}

void sys_read (syscall_request * req, const ucontext_t * context ){
   [>open ( char * "path", mode ) <] 
 //  DPRINT(DEBUG_INFO, " --READ-- System call handler\n");
   req->has_indirect_arguments=true; 
   req->indirect_arguments=1;
   req->args[0].content= (char *)req->arg1; 
   req->args[0].size = req->arg2 ; 
   req->args[0].argument_number = 1;
}
*/ 

/* CLONE */ 
u64_t clone_untrusted ( const ucontext_t * context) {

   /*DPRINT(DEBUG_INFO, " --CLONE-- System call handler\n");*/ /*char *stack = (char *)req->arg1; */
   /*char *child_stack=stack; */
   /*void *dummy;*/
   /*asm volatile( "mov %%rsp, %%rcx\n"*/
                 /*"mov %3, %%rsp\n"*/
                 /*"int $0\n"*/
                 /*"mov %%rcx, %%rsp\n"*/
                 /*: "=a"(stack), "=&c"(dummy)*/
                 /*: "a"(__NR_clone + 0xF000), "m"(stack)*/
                 /*: "memory");*/
 
   /*req->arg1=(long)stack;*/
   /*ucontext_t * uc = (struct ucontext *)stack;*/
   /*// copy state and signal mask of the untrusted process */
   /*memcpy(uc, context, sizeof(struct ucontext)); */
   /*uc->uc_mcontext.gregs[REG_RESULT]=0; */
   /*uc->uc_mcontext.gregs[REG_RSP]=(long)child_stack; */
}
void clone_trusted ( const syscall_request * request, int fd) {
  /*   if ( request.syscall_identifier == __NR_clone ) {*/
      /*long clone_flags = (long)   request.arg0; */
      /*char *stack      = (char *) request.arg1;*/
      /*int  *pid_ptr    = (int *)  request.arg2;*/
      /*int  *tid_ptr    = (int *)  request.arg3;*/
      /*void *tls_info   = (void *) request.arg4;*/
     
      /*request_result.result=clone(handle_new_thread,*/
                                    /*allocate_stack(STACK_SIZE), clone_flags,*/
                                    /*(void *)stack,pid_ptr, tls_info, tid_ptr); */

    /*} else {*/
      /*request_result.result = DoSyscall(&request);*/
    /*}*/
      /*request_result.cookie = request.cookie; */

    /*[>INTR_RES(write(local_info.fd_remote_process,(char *)&request_result,sizeof(request_result))<], nwrite); */

}

/* EXIT */ 
u64_t exit_untrusted ( const ucontext_t context) {
}
void exit_trusted (const syscall_request * request, int  fd) {
/*     if ( request.syscall_identifier == __NR_clone ) {*/
      /*long clone_flags = (long)   request.arg0; */
      /*char *stack      = (char *) request.arg1;*/
      /*int  *pid_ptr    = (int *)  request.arg2;*/
      /*int  *tid_ptr    = (int *)  request.arg3;*/
      /*void *tls_info   = (void *) request.arg4;*/
     
      /*request_result.result=clone(handle_new_thread,*/
                                    /*allocate_stack(STACK_SIZE), clone_flags,*/
                                    /*(void *)stack,pid_ptr, tls_info, tid_ptr); */

    /*} else {*/
      /*request_result.result = DoSyscall(&request);*/
    /*}*/
      /*request_result.cookie = request.cookie; */

    /*INTR_RES(write(local_info.fd_remote_process,(char *)&request_result,sizeof(request_result)), nwrite); */
}
