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



#define UNTRUSTED_START(arg) DPRINT(DEBUG_INFO, "--- %s Start untrusted handler\n", arg); 
#define UNTRUSTED_END(arg)   DPRINT(DEBUG_INFO, "--- %s End   untrusted handler\n", arg); 
#define TRUSTED_START(arg)   DPRINT(DEBUG_INFO, ">>> %s Start trusted handler\n",   arg);
#define TRUSTED_END(arg)     DPRINT(DEBUG_INFO, ">>> %s End   trusted handler\n",   arg);

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

  if (IS_STD_FD(uc->uc_mcontext.gregs[REG_ARG0]))
      return untrusted_default(uc); 

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

  if (IS_STD_FD(header->regs.arg0)) {
      trusted_default(fd, header); 
      return; 
  }

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
u64_t untrusted_mmap (const ucontext_t * uc) {
    
    struct syscall_result result;
    u64_t extra = 0;  
    int transfered =-1, size =-1; 
    char *buf = NULL; 
    unsigned int flags =0; 

    DPRINT(DEBUG_INFO, "MMPA Start untrusted handler\n");
 
    flags= uc->uc_mcontext.gregs[REG_ARG3];

    if (flags & MAP_ANONYMOUS) 
        return untrusted_default(uc);   
   
    if (send_syscall_header(uc, extra) < 0)
        die("Failed to send syscall_header"); 
  
    if(receive_syscall_result(&result) < 0 )
       die("Failed recieve_syscall_result"); 
          
    buf=(char *)result.result;
    size = (long)uc->uc_mcontext.gregs[REG_ARG1]; 
    
    DPRINT(DEBUG_INFO, "%d bytes mapped at %p \n", size, buf);  


    memset(buf, 0, size); 

    if((transfered=receive_extra(get_local_fd(), buf, size))< 0 ) 
            die("Failed extra result"); 

    DPRINT(DEBUG_INFO, "Transfered data %d \n", transfered);

    return (u64_t)result.result; 
  
}
void  trusted_mmap   ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  struct syscall_request request;
  unsigned int flags = 0; 

  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  flags= header->regs.arg3;

  if (flags & MAP_ANONYMOUS) { 
      trusted_default(fd, header);   
      return; 
  }

  DPRINT(DEBUG_INFO, ">>> MMPA Start trusted handler\n");
  
  assert(header->syscall_num == __NR_mmap); 
  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 
  
  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  result.extra = 0; 

  char * buf = (char *)result.result; 
  int   map_size = header->regs.arg1; 

  int transfered = send_result_with_extra(fd, &result, buf, map_size);  

  DPRINT(DEBUG_INFO, ">>> Transfered %d\n", transfered); 

  DPRINT(DEBUG_INFO, ">>> MMPA End   trusted handler\n");

};

/** OPENAT
  #include <fcntl.h>
  int openat(int dirfd, const char *pathname, int flags);
  int openat(int dirfd, const char *pathname, int flags, mode_t mode);
*/ 
u64_t untrusted_openat(const ucontext_t * uc ){

   struct syscall_result result; 
   int path_length = -1; 
   char * path = (char *)uc->uc_mcontext.gregs[REG_ARG1]; 
   u64_t extra =0;  
   int sent =-1; 
   struct iovec io[1];
   struct msghdr msg; 

   UNTRUSTED_START("OPENAT"); 
  
   memset(&msg, 0, sizeof(msg));
   memset(&result, 0, SIZE_RESULT); 

   // the compiler should ensure there is a null after the last character
   path_length = strlen(path) + 1;
   extra = path_length; 
  
   if (send_syscall_header(uc, extra)< 0)
      die("Send syscall header"); 
  
   // file path 
   io[0].iov_len=path_length; 
   io[0].iov_base = (char *)path; 

   msg.msg_iov=io; 
   msg.msg_iovlen=1; 

   sent = sendmsg(get_local_fd(), &msg, 0); 
   assert(sent ==  path_length);
  
   if(receive_syscall_result(&result) < 0 )
       die("Failede get_syscall_result"); 

  UNTRUSTED_END("OPENAT"); 
  return (u64_t)result.result; 
}

/* GETDENT
     int getdents(unsigned int fd, struct linux_dirent *dirp,
                    unsigned int count);
       Note: There is no glibc wrapper for this system call; see NOTES.
 * 
 */ 
u64_t untrusted_getdents(const ucontext_t * uc ){

  int received =-1; 
  struct syscall_result res; 
  int fd = get_local_fd(); 
  int cookie = get_local_tid(); 
  u64_t extra =0;  
  char *buf = NULL; 
  size_t size = 0; 
  
  UNTRUSTED_START("GETDENTS"); 

  buf = (char *)uc->uc_mcontext.gregs[REG_ARG1]; 
  size =  uc->uc_mcontext.gregs[REG_ARG2]; 

  if (send_syscall_header(uc, extra)< 0)
       die("Send syscall header");

  if ( (received = receive_result_with_extra(fd, &res, buf, size)) < 0)
      die("Recvmsg failed result stat"); 

  assert(received == (int)(SIZE_RESULT + size)); 
  assert(res.cookie == cookie); 

  UNTRUSTED_END("GETDENTS"); 
  
  return (u64_t)res.result; 
}
void  trusted_getdents   ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  struct syscall_request request;
  ssize_t transfered = -1; 

  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  UNTRUSTED_START("GETDENTS"); 

  assert(header->syscall_num == __NR_getdents); 
  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 
  
  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  result.extra = 0; 

  transfered = send_result_with_extra(fd, &result, (char *)header->regs.arg1, header->regs.arg2);  
  if ( transfered < 0) 
      die("Recvmsg (Fstat handler)"); 
 
  assert(transfered == (ssize_t)(SIZE_RESULT + header->regs.arg2)); 
  
  DPRINT(DEBUG_INFO, ">>> FSTAT End   trusted handler\n");
  return; 
}

/* WRITE */ 
u64_t untrusted_write(const ucontext_t * uc ){

   struct syscall_result result; 
   char * buf = NULL;  
   size_t size =0; 
   u64_t extra =0;  
 
   UNTRUSTED_START("WRITE");

   CLEAN_RES(&result); 

   buf = (char *)uc->uc_mcontext.gregs[REG_ARG1]; 
   size  = uc->uc_mcontext.gregs[REG_ARG2];
   extra = size; 
  
   if (send_syscall_header(uc, extra)< 0)
      die("Send syscall header"); 
  
   if (send_extra(get_local_fd(), buf, size) < 0) 
       die("Failed send extra (Untrudted write)"); 
  
   DPRINT(DEBUG_INFO, "Sent data"); 

   if(receive_syscall_result(&result) < 0 )
       die("Failede get_syscall_result"); 

   UNTRUSTED_END("WRITE"); 
   return (u64_t)result.result; 
}



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
