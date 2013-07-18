#include "handler.h"
#include "common.h"
#include "tls.h"
#include "sandbox.h"
#include "bpf-filter.h"
#include "trusted_thread.h"
#include "utils.h"

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
    int sent=-1; 
    struct iovec io[1];
    struct msghdr msg; 
  
    memset(&header, 0, sizeof(header)); 
    memset((void*)&msg, 0, sizeof(msg));  
    
    // set header 
    header.syscall_num = uc->uc_mcontext.gregs[REG_SYSCALL]; 
    header.address = uc->uc_mcontext.gregs[REG_PC]; 
    header.cookie  = get_local_tid(); 
    header.extra   = extra; 
    set_reg(&(header.regs), uc);
    
    io[0].iov_base = &header; 
    io[0].iov_len = SIZE_HEADER; 

    msg.msg_iov=io; 
    msg.msg_iovlen=1; 
   
    sent = sendmsg(fd, &msg, 0);
  
    if( sent < 0)
       die("Error sending registers");

   assert(sent ==  (SIZE_HEADER));
  
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
    struct syscall_result result;
    u64_t extra = 0;  
   
    syscall_num = ctx->uc_mcontext.gregs[REG_SYSCALL]; 
    
    DPRINT(DEBUG_INFO, "DEFAULT Start untrusted handler for < %s > \n", syscall_names[syscall_num]);
   
    if (send_syscall_header(ctx, extra) < 0)
        die("Failed to send syscall_header"); 
  
    if(receive_syscall_result(&result) < 0 )
       die("Failed recieve_syscall_result"); 

    DPRINT(DEBUG_INFO, "DEFAULT End   untrusted handler for < %s > \n", syscall_names[syscall_num]);
    return (u64_t)result.result; 
}
void trusted_default (int fd, const struct syscall_header *header){

  struct syscall_result result; 
  struct syscall_request request;

  memset(&result, 0, sizeof(result)); 
  memset(&request, 0, sizeof(request)); 

  DPRINT(DEBUG_INFO, ">>> Start DEFAULT trusted thread for system call < %s > \n",
            syscall_names[header->syscall_num]);

  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 

  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  result.extra = 0; 

  send_syscall_result(fd, &result); 

  DPRINT(DEBUG_INFO, ">>> End DEFAULT trusted thread for system call < %s > \n",
            syscall_names[header->syscall_num]);
 
}
void no_handler (int fd, const struct syscall_header *header){
  die("No handler has been called"); 
}


/*EXIT_GROUP */
void trusted_exit_group( int fd, const struct syscall_header *header) {
  
  struct syscall_result result; 
  struct syscall_request request;

  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  DPRINT(DEBUG_INFO, ">>> Trusted handler for < exit_group >\n");

  assert(header->syscall_num == __NR_exit_group);  

  result.result = 0x0;
  result.cookie = header->cookie; 
  result.extra = 0; 

  send_syscall_result(fd, &result); 
  // I should close also the untrusted connection
  close(fd); 

  DPRINT(DEBUG_INFO, ">>> Trusted handler for < exit_group > terminated\n");
  syscall(SYS_exit_group, 0); 
}
/*EXIT*/

/*OPEN*/
u64_t untrusted_open(const ucontext_t * uc ){

   struct syscall_result result; 
   int path_length = -1; 
   char * path = (char *)uc->uc_mcontext.gregs[REG_ARG0]; 
   u64_t extra =0;  
   struct iovec io[1];
   struct msghdr msg; 
   int sent =-1; 

   DPRINT(DEBUG_INFO, "--- START OPEN HANDLER\n"); 
  
   memset(&msg, 0, sizeof(msg));
   memset(&result, 0, SIZE_RESULT); 

   // the compiler should ensure there is a null after the last character
   path_length = strlen(path) + 1;
   extra = path_length; 
  
   // file path 
   io[0].iov_len=path_length; 
   io[0].iov_base = (char *)path; 

   msg.msg_iov=io; 
   msg.msg_iovlen=1; 

   if (send_syscall_header(uc, extra)< 0)
       die("Send syscall header"); 

   sent = sendmsg(get_local_fd(), &msg, 0); 
   assert(sent ==  path_length);
   
   // wait for the result 
  if(receive_syscall_result(&result) < 0 )
       die("Failede get_syscall_result"); 

  DPRINT(DEBUG_INFO, "--- END OPEN HANDLER\n"); 
  return (u64_t)result.result; 
}

/* FSSTAT 
 * int fstat(int fd, struct stat *buf);
 */ 
u64_t untrusted_fstat(const ucontext_t * uc ){

  struct iovec io[2];
  struct msghdr msg; 
  int received =-1; 
  struct syscall_result res; 
  int fd = get_local_fd(); 
  int cookie = get_local_tid(); 
  u64_t extra =0;  
  
  DPRINT(DEBUG_INFO, "--- FSTAT Start untrusted handler\n"); 

  if (send_syscall_header(uc, extra)< 0)
       die("Send syscall header"); 

   // it receives the result header plus the struct fstat 
   // whihc has to be conpied in the correct memory position 
  CLEAN_MSG(&msg); 
  CLEAN_RES(&res); 

  io[0].iov_len = SIZE_RESULT; 
  io[0].iov_base = &res; 

  // update the value
  io[1].iov_len  = sizeof(struct stat); 
  io[1].iov_base = (char *)uc->uc_mcontext.gregs[REG_ARG1]; 

  msg.msg_iov=io;     
  msg.msg_iovlen=2; 

  INTR_RES(recvmsg(fd, &msg,0), received); 
 
  if ( received < 0) 
      die("Recvmsg failed result stat"); 

  assert(res.cookie == cookie); 
  assert(received == SIZE_RESULT + sizeof( struct stat)); 

  DPRINT(DEBUG_INFO, "--- FSTAT End   untrusted handler\n"); 
  return (u64_t)res.result; 
}
void  trusted_fstat   ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  struct syscall_request request;

  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  DPRINT(DEBUG_INFO, ">>> FSTAT Start trusted handler\n");

  assert(header->syscall_num == __NR_fstat); 
  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 
  
  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  result.extra = 0; 

  // send results with the struct as well 
  struct iovec io[2];
  struct msghdr msg; 
  int transfered=-1; 

  CLEAN_MSG(&msg);
  memset(io, 0, sizeof(io)); 
    
  // result header 
  io[0].iov_len=SIZE_RESULT; 
  io[0].iov_base=&result;
  // result fstat
  io[1].iov_len = sizeof(struct stat); 
  io[1].iov_base = (char *)header->regs.arg1; 
    // IOV struct 
  msg.msg_iov=io;
  msg.msg_iovlen=2; 
 
  transfered=sendmsg(fd,&msg, 0); 
  if ( transfered < 0) 
      die("Recvmsg (Fstat handler)"); 
  assert(transfered == SIZE_RESULT +sizeof(struct stat)); 
  
  DPRINT(DEBUG_INFO, ">>> FSTAT End   trusted handler\n");
  return; 
}

/** MMAP
    #include <sys/mman.h>
    void *mmap(void *addr, size_t length, int prot, int flags,int fd, off_t offset);
    int munmap(void *addr, size_t length)
 **/ 
extern u64_t untrusted_mmap (const ucontext_t * uc) {
  
  struct syscall_result res; 
  int fd = get_local_fd(); 
  u64_t extra =0;  
  char * buf = NULL;  
  int buf_size =  uc->uc_mcontext.gregs[REG_ARG1];

  DPRINT(DEBUG_INFO, "--- MMPA Start untrusted handler\n"); 
  
  if (send_syscall_header(uc, extra)< 0)
          die("Send syscall header"); 
  // I cannot know the address returned by mmap
  if (receive_syscall_result(&res) < 0)
        die("Error reading result from mmap"); 
  buf = (char *)res.result; 
 
  fpritnf(stderr, "%x %p", res.result, buf); 

  if (receive_extra_result(fd, buf, buf_size) < 0)
      die("Error receive extra result MMAP"); 

  DPRINT(DEBUG_INFO, "--- MMPA End   untrusted handler\n");

  return (u64_t)res.result; 
  
}
extern void  trusted_mmap   ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  struct syscall_request request;

  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  DPRINT(DEBUG_INFO, ">>> MMPA Start trusted handler\n");
  
  assert(header->syscall_num == __NR_mmap); 
  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 
  
  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  result.extra = 0; 

  char * buf = (char *)result.result; 
  int   map_size = header->regs.arg1; 

  printf("cookie %d\n", result.cookie); 
  send_result_with_extra(fd, &result, map_size, buf);  
  printf("cookie %d\n", result.cookie); 
  DPRINT(DEBUG_INFO, ">>> MMPA End   trusted handler\n");

};



/*[> CLONE <] */
/*u64_t clone_untrusted ( const ucontext_t * context) {*/

/*   DPRINT(DEBUG_INFO, " --CLONE-- System call handler\n"); char *stack = (char *)req->arg1; */
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
    /*copy state and signal mask of the untrusted process */
   /*memcpy(uc, context, sizeof(struct ucontext)); */
   /*uc->uc_mcontext.gregs[REG_RESULT]=0; */
   /*uc->uc_mcontext.gregs[REG_RSP]=(long)child_stack; */
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
