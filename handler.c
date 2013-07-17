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
#include <assert.h> 
#include <sys/syscall.h> 


int receive_syscall_result (struct syscall_result * res){
    int received;
    int fd = get_local_fd(); 
    pid_t tid = get_local_tid(); 

    INTR_RES(read(fd, (char *)res, SIZE_RESULT), received); 

    if (res->cookie != tid || received != SIZE_RESULT)
        die("cookie verification failed (result)"); 

    return received; 
}
void set_reg (struct syscall_registers * reg, const ucontext_t * ctx) {
   memset(reg, 0, SIZE_REGISTERS); 
   reg->arg0 = ctx->uc_mcontext.gregs[REG_ARG0]; 
   reg->arg1 = ctx->uc_mcontext.gregs[REG_ARG1]; 
   reg->arg2 = ctx->uc_mcontext.gregs[REG_ARG2]; 
   reg->arg3 = ctx->uc_mcontext.gregs[REG_ARG3]; 
   reg->arg4 = ctx->uc_mcontext.gregs[REG_ARG4];
   reg->arg5 = ctx->uc_mcontext.gregs[REG_ARG5]; 
}
ssize_t send_syscall_header(const ucontext_t * uc, int extra) { 

    struct syscall_header header; 
    int fd = get_local_fd();
    size_t sent=-1; 

    memset(&header, 0, sizeof(header)); 

    DPRINT(DEBUG_INFO, "System call header\n"); 
    
    header.syscall_num = uc->uc_mcontext.gregs[REG_SYSCALL]; 
    header.address = uc->uc_mcontext.gregs[REG_PC]; 
    header.cookie  = get_local_tid(); 
    header.extra   = extra; 

    INTR_RES(write(fd, (char *)&header, SIZE_HEADER), sent);

    DPRINT(DEBUG_INFO, "System call header sent\n"); 

    if ( sent != SIZE_HEADER)
        die("Error sending header"); 

    return sent; 
}
ssize_t send_syscall_result(int fd, struct syscall_result * res) {
 
  struct iovec io[1];
  struct msghdr msg; 
  int sent =-1; 

  CLEAN_MSG(&msg); 

  io[0].iov_len = SIZE_RESULT; 
  io[0].iov_base = res; 
 
  msg.msg_iov=io; 
  msg.msg_iovlen=1; 

  sent = sendmsg(fd, &msg,0);
  
  if (sent < 0) 
        die("Failed sending syscall arguments"); 

  assert( sent == SIZE_RESULT); 

  return sent; 

}

/**********************************************************************
 *                          DEFAULT                                   *
 **********************************************************************/
u64_t untrusted_default(const ucontext_t *ctx ){
   
    int syscall_num = -1; 
    struct syscall_registers regs; 
    struct syscall_result result;
    int sent=-1; 
    u64_t extra = 0;  
    struct iovec io[IOV_DEFAULT];
    struct msghdr msg; 
  
    syscall_num = ctx->uc_mcontext.gregs[REG_SYSCALL]; 

    DPRINT(DEBUG_INFO, "Start DEFAULT handler for < %s > \n", syscall_names[syscall_num]);

    memset((void*)&regs, 0, sizeof(regs)); 
    memset((void*)&result,  0, sizeof(result)); 
    memset((void*)&msg, 0, sizeof(msg));  
    // reg 
    set_reg(&regs, ctx);
    io[REG].iov_len=SIZE_REGISTERS; 
    io[REG].iov_base=&regs; 
   
   if (send_syscall_header(ctx, extra)< 0)
      die("Send syscall header"); 
  
   msg.msg_iov=io; 
   msg.msg_iovlen=IOV_DEFAULT; 
   
   sent = sendmsg(get_local_fd(), &msg, 0);
  
   if( sent < 0)
       die("Error sending registers");

   DPRINT(DEBUG_INFO, " Sent registers %d \n", sent);
   // wait for the result 
   assert(sent ==  SIZE_REGISTERS);
   
   if(receive_syscall_result(&result) < 0 )
       die("Failede get_syscall_result"); 

   DPRINT(DEBUG_INFO, " End DEFAULT handler for < %s > \n", syscall_names[syscall_num]);
   return (u64_t)result.result; 
}
void trusted_default (int fd, const struct syscall_header *header, const struct syscall_registers * regs){

  struct syscall_result result; 
  struct syscall_request request;

  memset(&result, 0, sizeof(result)); 
  memset(&request, 0, sizeof(request)); 

  DPRINT(DEBUG_INFO, "Start DEFAULT trusted thread for system call < %s > \n",
            syscall_names[header->syscall_num]);

  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, regs, SIZE_REGISTERS); 

  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  result.extra = 0; 

  send_syscall_result(fd, &result); 

  DPRINT(DEBUG_INFO, "End DEFAULT trusted thread for system call < %s > \n",
            syscall_names[header->syscall_num]);
 
}

/*EXIT_GROUP */
void trusted_exit_group( int fd, const struct syscall_header *header, const struct syscall_registers *regs) {
  
  struct syscall_result result; 
  struct syscall_request request;

  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  DPRINT(DEBUG_INFO, "Trusted handler for < exit_group >\n");

  assert(header->syscall_num == __NR_exit_group);  

  result.result = 0;
  result.cookie = header->cookie; 
  result.extra = 0; 
  
  send_syscall_result(fd, &result); 

  // I should close also the untrusted connection
  close(fd); 

  DPRINT(DEBUG_INFO, "Trusted handler for < exit_group > terminated\n");

  syscall(SYS_exit_group); 
}
/*EXIT*/

/*OPEN*/
u64_t open_untrusted(const ucontext_t * uc ){

   struct syscall_registers regs; 
   struct syscall_result result; 
   int path_length = -1; 
   char * path = (char *)uc->uc_mcontext.gregs[REG_ARG0]; 
   u64_t extra =0;  
   struct iovec io[IOV_OPEN];
   struct msghdr msg; 
   int sent =-1; 

   DPRINT(DEBUG_INFO, " --  START OPEN HANDLER\n"); 
  
   memset(&msg, 0, sizeof(msg));
   memset(&result, 0, SIZE_RESULT); 

   // the compiler should ensure there is a null after the last character
   path_length = strlen(path) + 1;
   extra = path_length; 

   // IOV 0 register 
   set_reg(&regs, uc); 
   io[REG].iov_len=SIZE_REGISTERS; 
   io[REG].iov_base=&regs; 
   
   // file path 
   io[1].iov_len=path_length; 
   io[1].iov_base = (char *)path; 

   msg.msg_iov=io; 
   msg.msg_iovlen=IOV_OPEN; 

   if (send_syscall_header(uc, extra)< 0)
       die("Send syscall header"); 

   sent = sendmsg(get_local_fd(), &msg, 0); 
   assert(sent ==  SIZE_REGISTERS + path_length);
  
   // wait for the result 
  if(receive_syscall_result(&result) < 0 )
       die("Failede get_syscall_result"); 

  DPRINT(DEBUG_INFO, " -- END OPEN HANDLER\n"); 
  return (u64_t)result.result; 
}


/*[> CLONE <] */
/*u64_t clone_untrusted ( const ucontext_t * context) {*/

   /*[>DPRINT(DEBUG_INFO, " --CLONE-- System call handler\n");*/ /*char *stack = (char *)req->arg1; <]*/
   /*[>char *child_stack=stack; <]*/
   /*[>void *dummy;<]*/
   /*[>asm volatile( "mov %%rsp, %%rcx\n"<]*/
                 /*[>"mov %3, %%rsp\n"<]*/
                 /*[>"int $0\n"<]*/
                 /*[>"mov %%rcx, %%rsp\n"<]*/
                 /*[>: "=a"(stack), "=&c"(dummy)<]*/
                 /*[>: "a"(__NR_clone + 0xF000), "m"(stack)<]*/
                 /*[>: "memory");<]*/
 
   /*[>req->arg1=(long)stack;<]*/
   /*[>ucontext_t * uc = (struct ucontext *)stack;<]*/
   /*[>// copy state and signal mask of the untrusted process <]*/
   /*[>memcpy(uc, context, sizeof(struct ucontext)); <]*/
   /*[>uc->uc_mcontext.gregs[REG_RESULT]=0; <]*/
   /*[>uc->uc_mcontext.gregs[REG_RSP]=(long)child_stack; <]*/
/*}*/
/*void clone_trusted ( const syscall_request * request, int fd) {*/
  /*[>   if ( request.syscall_identifier == __NR_clone ) {<]*/
      /*[>long clone_flags = (long)   request.arg0; <]*/
      /*[>char *stack      = (char *) request.arg1;<]*/
      /*[>int  *pid_ptr    = (int *)  request.arg2;<]*/
      /*[>int  *tid_ptr    = (int *)  request.arg3;<]*/
      /*[>void *tls_info   = (void *) request.arg4;<]*/
     
      /*[>request_result.result=clone(handle_new_thread,<]*/
                                    /*[>allocate_stack(STACK_SIZE), clone_flags,<]*/
                                    /*[>(void *)stack,pid_ptr, tls_info, tid_ptr); <]*/

    /*[>} else {<]*/
      /*[>request_result.result = DoSyscall(&request);<]*/
    /*[>}<]*/
      /*[>request_result.cookie = request.cookie; <]*/

    /*[>[>INTR_RES(write(local_info.fd_remote_process,(char *)&request_result,sizeof(request_result))<], nwrite); <]*/

/*}*/

/*[> EXIT <] */
/*u64_t exit_untrusted ( const ucontext_t context) {*/
/*}*/
/*void exit_trusted (const syscall_request * request, int  fd) {*/
/*[>     if ( request.syscall_identifier == __NR_clone ) {<]*/
      /*[>long clone_flags = (long)   request.arg0; <]*/
      /*[>char *stack      = (char *) request.arg1;<]*/
      /*[>int  *pid_ptr    = (int *)  request.arg2;<]*/
      /*[>int  *tid_ptr    = (int *)  request.arg3;<]*/
      /*[>void *tls_info   = (void *) request.arg4;<]*/
     
      /*[>request_result.result=clone(handle_new_thread,<]*/
                                    /*[>allocate_stack(STACK_SIZE), clone_flags,<]*/
                                    /*[>(void *)stack,pid_ptr, tls_info, tid_ptr); <]*/

    /*[>} else {<]*/
      /*[>request_result.result = DoSyscall(&request);<]*/
    /*[>}<]*/
      /*[>request_result.cookie = request.cookie; <]*/

    /*[>INTR_RES(write(local_info.fd_remote_process,(char *)&request_result,sizeof(request_result)), nwrite); <]*/
/*}*/

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
