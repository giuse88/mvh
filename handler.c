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
#include <sys/sendfile.h>
#include <sys/epoll.h>
#include <assert.h> 
#include <stdlib.h> 
#include <sched.h> 



#define UNTRUSTED_START(arg) DPRINT(DEBUG_INFO, "--- %s Start untrusted handler\n", arg); 
#define UNTRUSTED_END(arg)   DPRINT(DEBUG_INFO, "--- %s End   untrusted handler\n", arg); 
#define TRUSTED_START(arg)   DPRINT(DEBUG_INFO, ">>> %s Start trusted handler\n",   arg);
#define TRUSTED_END(arg)     DPRINT(DEBUG_INFO, ">>> %s End   trusted handler\n",   arg);

off_t get_file_size (int fd) {

  struct stat file; 
  if ( fstat(fd, &file) < 0) 
      die("Fstat");
  return file.st_size; 
}


int receive_syscall_result (struct syscall_result * res){
    int received;
    int fd = get_local_fd(); 
    pid_t tid = get_local_tid(); 

    INTR_RES(read(fd, (char *)res, SIZE_RESULT), received); 

    DPRINT(DEBUG_INFO, "TID %d, FD %d received %lu %lu\n", tid, fd,res->cookie , res->result);

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

  DPRINT(DEBUG_INFO, ">>> DEFAULT trusted thread for system call <%s> START \n",
            syscall_names[header->syscall_num]);

  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 

  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  result.extra = 0; 

  send_syscall_result(fd, &result); 

  DPRINT(DEBUG_INFO, ">>> DEFAULT trusted thread for system call <%s> END \n",
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

   UNTRUSTED_START("OPEN"); 
   
   CLEAN_RES(&result); 

   path_length = strlen(path) + 1;
   extra = path_length; 

   if (send_syscall_header(uc, extra)< 0)
       die("Send syscall header"); 

  if (send_extra(get_local_fd(), path, path_length) < 0) 
       die("Failed send extra (OPEN)"); 
  
  if(receive_syscall_result(&result) < 0 )
       die("Failede get_syscall_result(OPEN)"); 
 
  DPRINT(DEBUG_INFO, "OPEN(\"%s\"(%d),0x%X)=%d\n", path, path_length,
     (unsigned int)  uc->uc_mcontext.gregs[REG_ARG1], (int)result.result); 

  UNTRUSTED_END("OPEN"); 

  return (u64_t)result.result; 
}

u64_t untrusted_fstat(const ucontext_t * uc ){

  struct syscall_result res; 
  int fd = get_local_fd(); 
  u64_t extra =0;  
  ssize_t transfered=-1; 
  struct stat * stat_info = NULL; 

  UNTRUSTED_START("FSTAT"); 

  if (IS_STD_FD(uc->uc_mcontext.gregs[REG_ARG0]))
      return untrusted_default(uc); 

  if (send_syscall_header(uc, extra)< 0)
       die("Send syscall header"); 

  stat_info = (struct stat *)uc->uc_mcontext.gregs[REG_ARG1]; 
  transfered=receive_result_with_extra(fd, &res, (char *)stat_info, sizeof ( struct stat) ); 

  if ( transfered < 0) 
      die("Receive resutl with extra FSTAT"); 
  
  CHECK(transfered, sizeof(struct stat) + SIZE_RESULT, res.extra); 

  DPRINT(DEBUG_INFO, "FSTAT(%ld, 0x%lX) = %ld\n", (long int)uc->uc_mcontext.gregs[REG_ARG0], (unsigned long)stat_info, res.result); 
 
  UNTRUSTED_END("FSTAT"); 
  return (u64_t)res.result; 
}
void  trusted_fstat   ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  struct syscall_request request;
  ssize_t transfered =-1; 

  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  TRUSTED_START("FSTAT"); 

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

  transfered =send_result_with_extra(fd, &result, (char *)header->regs.arg1, sizeof (struct stat));  
  if ( transfered < 0) 
      die("recvmsg (fstat handler)"); 

  CHECK(transfered, sizeof(struct stat) + SIZE_RESULT, result.extra); 
  
  DPRINT(DEBUG_INFO, "FSTAT(%ld, 0x%lX) = %ld\n", header->regs.arg0, header->regs.arg1, result.result); 
  
  TRUSTED_END("FSTAT"); 
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
    ssize_t transfered =-1;
    size_t size =0; 
    char *buf = NULL; 
    unsigned int flags =0; 

    UNTRUSTED_START("MMPA"); 

    flags= uc->uc_mcontext.gregs[REG_ARG3];

    if (flags & MAP_ANONYMOUS) 
        return untrusted_default(uc);   
   
    if (send_syscall_header(uc, extra) < 0)
        die("Failed to send syscall_header"); 
  
    if(receive_syscall_result(&result) < 0 )
       die("Failed recieve_syscall_result"); 
          
    buf=(char *)result.result;
    size = result.extra; 


    DPRINT(DEBUG_INFO, "--- %lu bytes mapped at %p \n", size, buf);  
    memset(buf, 0, size); 
    DPRINT(DEBUG_INFO, "--- Memory verified\n");

    if((transfered=receive_extra(get_local_fd(), buf, size))< 0 ) 
            die("Failed extra result"); 

    CHECK(transfered, size, 0);  
    DPRINT(DEBUG_INFO, "--- Transfered data : %ld \n", transfered);

    DPRINT(DEBUG_INFO, "mmap(0x%lX, %lu, 0x%lX, 0x%lX, %ld, %lu) = 0x%lX\n", 
       (long unsigned) uc->uc_mcontext.gregs[REG_ARG0], (long unsigned)uc->uc_mcontext.gregs[REG_ARG1],
       (long unsigned) uc->uc_mcontext.gregs[REG_ARG2], (long unsigned)uc->uc_mcontext.gregs[REG_ARG3],
       (long) uc->uc_mcontext.gregs[REG_ARG4], (long unsigned)uc->uc_mcontext.gregs[REG_ARG5],
        result.result); 

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

  TRUSTED_START("MMPA");
  
  assert(header->syscall_num == __NR_mmap); 
  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 
  
  result.result = do_syscall(&request);
  result.cookie = header->cookie; 

  char * buf = (char *)result.result; 
  int file_fd = header->regs.arg4;
  size_t size_file = get_file_size(file_fd); 
  size_t map_size = header->regs.arg1; 
  size_t real_map_size = (map_size > size_file ) ? size_file : map_size;  

  DPRINT(DEBUG_INFO, ">>> MMAP  result %lx, Size Memory area %lu\n", result.result, map_size); 
  DPRINT(DEBUG_INFO, ">>> Real size of the file in memory %ld\n", size_file); 
  DPRINT(DEBUG_INFO, ">>> Real amount of memory mapped %ld\n", real_map_size); 
  
  // sanity check 
  int j=0;
  for (int i=0; i < (int)real_map_size; i++)
    j=buf[i]; 
  j+=j; 

  DPRINT(DEBUG_INFO, ">>> Memory verified\n"); 
  result.extra = real_map_size; 
  int transfered = send_result_with_extra(fd, &result, buf, real_map_size);  
  DPRINT(DEBUG_INFO, ">>> Transfered %d\n", transfered);
  
  CHECK(transfered, real_map_size + SIZE_RESULT, 0); 

  DPRINT(DEBUG_INFO, "mmap(%lX, %ld, 0x%lX, 0x%lx, %ld, %lu) = 0x%lX\n",
      header->regs.arg0, header->regs.arg1,
      header->regs.arg2, header->regs.arg3,
      header->regs.arg4, header->regs.arg5,
      result.result); 
  TRUSTED_END("MMPA");

  return; 
}

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
   ssize_t transfered = -1; 

   UNTRUSTED_START("WRITE");

   CLEAN_RES(&result); 

   buf = (char *)uc->uc_mcontext.gregs[REG_ARG1]; 
   size  = uc->uc_mcontext.gregs[REG_ARG2];
   extra = size; 
 
   DPRINT(DEBUG_INFO, " write(%d, %s, %lu)\n", (int)uc->uc_mcontext.gregs[REG_ARG0], buf, size); 

   if (send_syscall_header(uc, extra)< 0)
      die("Send syscall header"); 
  
   if ( (transfered = send_extra(get_local_fd(), buf, size)) < 0) 
       die("Failed send extra (Untrudted write)"); 
  
   DPRINT(DEBUG_INFO, "Sent data %ld", transfered); 

   if(receive_syscall_result(&result) < 0 )
       die("Failede get_syscall_result"); 

   UNTRUSTED_END("WRITE"); 
   return (u64_t)result.result; 
}

u64_t untrusted_read(const ucontext_t * uc ){

  ssize_t transfered =0; 
  struct syscall_result res; 
  int fd = get_local_fd(); 
  int cookie = get_local_tid(); 
  u64_t extra =0;  
  char * buf = NULL; 
  size_t size =0; 

  UNTRUSTED_START("READ"); 

  if (IS_STD_FD(uc->uc_mcontext.gregs[REG_ARG0]))
      return untrusted_default(uc); 

  CLEAN_RES(&res); 
  
  if (send_syscall_header(uc, extra)< 0)
       die("Send syscall header"); 

  buf  = (char *)uc->uc_mcontext.gregs[REG_ARG1]; 
  size = uc->uc_mcontext.gregs[REG_ARG2]; 
  transfered= receive_result_with_extra(fd, &res, buf, size); 

  if ( transfered < 0) 
      die("Recvmsg failed result stat"); 

  assert(res.cookie == cookie);

  CHECK(transfered, size + SIZE_RESULT, res.extra); 
  
  UNTRUSTED_END("READ"); 

  return (u64_t)res.result; 
}
void  trusted_read  ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  struct syscall_request request;
  ssize_t transfered =0; 

  TRUSTED_START("READ"); 

  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  assert(header->syscall_num == __NR_read); 

  if (IS_STD_FD(header->regs.arg0)) {
      trusted_default(fd, header); 
      return; 
  }

  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 
  
  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  result.extra = 0; 

  transfered =send_result_with_extra(fd, &result, (char *)header->regs.arg1, header->regs.arg2);  
  if ( transfered < 0) 
      die("Recvmsg (Fstat handler)"); 
  
  CHECK(transfered, header->regs.arg2 + SIZE_RESULT, result.extra); 

  TRUSTED_END("READ"); 

  return; 
}

u64_t untrusted_ioctl(const ucontext_t * uc ){

  int transfered =-1; 
  struct syscall_result res; 
  int fd = get_local_fd(); 
  int cookie = get_local_tid(); 
  char *buf = NULL; 
  size_t size = 0; 
  int extra =0;

  UNTRUSTED_START("IOCTL"); 

  if (IS_STD_FD(uc->uc_mcontext.gregs[REG_ARG0]))
      return untrusted_default(uc); 

  if (send_syscall_header(uc, extra)< 0)
       die("Send syscall header"); 

  buf = (char *)uc->uc_mcontext.gregs[REG_ARG2]; 
  size = get_size_from_cmd((int)uc->uc_mcontext.gregs[REG_ARG1]); 

  DPRINT(DEBUG_INFO, "IOCTL buffer has size %ld\n", size); 
 
  if((transfered = receive_result_with_extra(fd, &res, buf, size)) < 0)
     die("Receive result error (IOCTL)"); 
 
  DPRINT(DEBUG_INFO, "IOCTL received %d, content %d\n", transfered, *(int*)buf); 
  
  CHECK(transfered, size + SIZE_RESULT, res.extra);  
  assert(res.cookie == cookie); 

  UNTRUSTED_END("IOCTL");  
  return (u64_t)res.result; 
}

void  trusted_ioctl ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  struct syscall_request request;
  ssize_t transfered = -1; 

  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  TRUSTED_START("IOCTL"); 

  assert(header->syscall_num == __NR_ioctl);

  if (IS_STD_FD(header->regs.arg0)) {
      trusted_default(fd, header); 
      return; 
  }
  
  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 
 
  size_t size_buf = get_size_from_cmd(header->regs.arg1);
  char *buf = (char *)header->regs.arg2; 

  /*for (int i=0; i< size_buf; i++)*/
    /*printf("%d : %X\n",i, *(buf + i)); */
 
  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  result.extra = (int)result.result > 0 ? size_buf : 0; 
 
  /*for (int i=0; i< size_buf; i++)*/
    /*printf("%d : %X\n", i,  *(buf + i)); */

  transfered = send_result_with_extra(fd, &result, buf, size_buf);  
  if ( transfered < 0) 
      die("Recvmsg (Fstat handler)"); 
 
  assert(transfered == (ssize_t)(SIZE_RESULT + size_buf) || (transfered == (SIZE_RESULT) && (int)result.result < 0)); 
  
  TRUSTED_END("IOCTL"); 

  return; 
}

u64_t untrusted_getcwd(const ucontext_t * uc ){

  ssize_t received =0; 
  struct syscall_result res; 
  int fd = get_local_fd(); 
  int cookie = get_local_tid(); 
  u64_t extra =0;  
  char * buf = NULL; 
  size_t size =0; 

  UNTRUSTED_START("GETCWD"); 

  CLEAN_RES(&res); 
 
  buf  = (char *)uc->uc_mcontext.gregs[REG_ARG0]; 
  size = uc->uc_mcontext.gregs[REG_ARG1];
  extra = size; 
  
  if (send_syscall_header(uc, extra)< 0)
       die("Send syscall header"); 

  received= receive_result_with_extra(fd, &res, buf, size); 

  if ( received < 0) 
      die("Recvmsg failed result stat"); 

  assert(res.cookie == cookie); 
  assert((size_t)received == (SIZE_RESULT + size)); 
  
  DPRINT(DEBUG_INFO, "The current working directory is %s\n", buf);  
  
  UNTRUSTED_END("READ"); 

  return (u64_t)res.result; 
}
void  trusted_getcwd  ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  struct syscall_request request;
  ssize_t transfered =0; 

  TRUSTED_START("GETCWD"); 

  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  assert(header->syscall_num == __NR_getcwd); 

  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 
  
  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  result.extra = 0; 

  transfered =send_result_with_extra(fd, &result, (char *)header->regs.arg0, header->regs.arg1);  
  if ( transfered < 0) 
      die("recvmsg (fstat handler)"); 

  CHECK(transfered, header->regs.arg1 + SIZE_RESULT, result.extra); 

  TRUSTED_END("GETCWD"); 

  return; 
}
u64_t untrusted_stat_priv(const ucontext_t * uc ){

  struct syscall_result res; 
  u64_t extra =0;  
  char * path = NULL; 
  size_t path_length = 0; 
  
  UNTRUSTED_START("STAT"); 

  // the compiler should ensure there is a null after the last character
  path = (char *)uc->uc_mcontext.gregs[REG_ARG0];  
  path_length = strlen(path) + 1;
  extra = path_length; 
 
  DPRINT(DEBUG_INFO, "Path %s, Path length %lu\n", path, path_length); 

  if (send_syscall_header(uc, extra)< 0)
       die("Send syscall header"); 

  if (send_extra(get_local_fd(), path,path_length) < 0) 
       die("Failed send extra (STAT)"); 
  
  if(receive_syscall_result(&res) < 0 )
       die("Failede get_syscall_result"); 

  UNTRUSTED_END("STAT"); 
  return (u64_t)res.result; 
}

u64_t untrusted_stat_pub(const ucontext_t * uc ){

  struct syscall_result res; 
  int fd = get_local_fd(); 
  u64_t extra =0;  
  char * path = NULL; 
  size_t path_length = 0; 
  ssize_t transfered =-1; 
  struct stat * stat_info =NULL; 
  
  UNTRUSTED_START("STAT"); 

  // the compiler should ensure there is a null after the last character
  path = (char *) uc->uc_mcontext.gregs[REG_ARG0];  
  stat_info = ( struct stat *)uc->uc_mcontext.gregs[REG_ARG1];  
  path_length = strlen(path) + 1;
  extra = path_length; 
  
  DPRINT(DEBUG_INFO, "Path %s, Path length %lu\n", path, path_length); 
  
  if (send_syscall_header(uc, extra)< 0)
       die("Send syscall header"); 

  if (send_extra(get_local_fd(), path, path_length) < 0) 
       die("Failed send extra (STAT)"); 

  transfered= receive_result_with_extra(fd, &res, (char *)stat_info, sizeof ( struct stat) ); 
  if ( transfered < 0) 
      die("Recvmsg failed result stat"); 
  
  CHECK(transfered, sizeof(struct stat) + SIZE_RESULT, res.extra); 

  UNTRUSTED_END("STAT"); 
  return (u64_t)res.result; 
}
void  trusted_stat   ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  struct syscall_request request;
  ssize_t transfered =-1; 
  
  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  TRUSTED_START("STAT"); 
  
  assert(header->syscall_num == __NR_stat); 
  
  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 
  
  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  result.extra = 0; 

  transfered =send_result_with_extra(fd, &result, (char *)header->regs.arg1, sizeof (struct stat));  
  if ( transfered < 0) 
      die("recvmsg (fstat handler)"); 

  CHECK(transfered, sizeof(struct stat) + SIZE_RESULT, result.extra); 
  
  TRUSTED_END("STAT"); 

  return; 
}

u64_t untrusted_setsockopt(const ucontext_t * uc ){

   struct syscall_result result; 
   char * buf = NULL;  
   size_t size =0; 
   u64_t extra =0;  
 
   UNTRUSTED_START("SETSOCKOPT");

   CLEAN_RES(&result); 

   buf = (char *)uc->uc_mcontext.gregs[REG_ARG3]; 
   size  = uc->uc_mcontext.gregs[REG_ARG4];
   extra = size; 
  
   if (send_syscall_header(uc, extra)< 0)
      die("Send syscall header"); 
  
   if (send_extra(get_local_fd(), buf, size) < 0) 
       die("Failed send extra (Untrudted write)"); 
  
   DPRINT(DEBUG_INFO, "Sent data"); 

   if(receive_syscall_result(&result) < 0 )
       die("Failede get_syscall_result"); 

   UNTRUSTED_END("SETSOCKOPT"); 
   return (u64_t)result.result; 
}

u64_t untrusted_bind(const ucontext_t * uc ){

   struct syscall_result result; 
   char * buf = NULL;  
   size_t size =0; 
   u64_t extra =0;  
 
   UNTRUSTED_START("BIND");

   CLEAN_RES(&result); 

   buf = (char *)uc->uc_mcontext.gregs[REG_ARG1]; 
   size  = uc->uc_mcontext.gregs[REG_ARG2];
   extra = size; 
  
   if (send_syscall_header(uc, extra)< 0)
      die("Send syscall header"); 
  
   if (send_extra(get_local_fd(), buf, size) < 0) 
       die("Failed send extra (Untrudted write)"); 
  
   if(receive_syscall_result(&result) < 0 )
       die("Failede get_syscall_result"); 

   UNTRUSTED_END("BIND"); 
   return (u64_t)result.result; 
}

u64_t untrusted_epoll_ctl(const ucontext_t * uc ){

   struct syscall_result result; 
   char * buf = NULL;  
   size_t size =0; 
   u64_t extra =0;  
 
   UNTRUSTED_START("EPOLL_CTL");

   CLEAN_RES(&result); 

   buf = (char *)uc->uc_mcontext.gregs[REG_ARG3]; 
   size  = sizeof(struct epoll_event);
   extra = size; 
  
   if (send_syscall_header(uc, extra)< 0)
      die("Send syscall header"); 
  
   if (send_extra(get_local_fd(), buf, size) < 0) 
       die("Failed send extra (Untrudted write)"); 
  
   if(receive_syscall_result(&result) < 0 )
       die("failede get_syscall_result"); 

   UNTRUSTED_END("EPOLL_CTL"); 
   return (u64_t)result.result; 
}

u64_t untrusted_epoll_wait(const ucontext_t * uc ){

   struct syscall_result res; 
   char * buf = NULL;  
   size_t size =0; 
   int events_numbers = 0; 
   u64_t extra =0;  
   int fd =  get_local_fd();
   u64_t cookie = get_local_tid();
   ssize_t  transfered = -1; 


   UNTRUSTED_START("EPOLL_WAIT");
   CLEAN_RES(&res); 

   buf = (char *)uc->uc_mcontext.gregs[REG_ARG1]; 
   events_numbers = (int)uc->uc_mcontext.gregs[REG_ARG2]; 
   size  = sizeof(struct epoll_event) * events_numbers;
   extra = size; 

   DPRINT(DEBUG_INFO, "Number of events %d\n", events_numbers); 

   if (send_syscall_header(uc, extra)< 0)
      die("Send syscall header"); 
  
   transfered= receive_result_with_extra(fd, &res, buf, size); 
   if ( transfered < 0) 
      die("Recvmsg failed result stat"); 

   assert((u64_t)res.cookie == cookie);
   CHECK(transfered, size + SIZE_RESULT, res.extra); 
 
   UNTRUSTED_END("EPOLL_WAIT"); 
   return (u64_t)res.result; 
}

void  trusted_epoll_wait ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  struct syscall_request request;
  ssize_t transfered = -1; 
  size_t size =0;

  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  TRUSTED_START("EPOLL_WAIT"); 

  assert(header->syscall_num == __NR_epoll_wait);
  request.syscall_identifier = header->syscall_num;

  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 

  size = header->regs.arg2 * sizeof( struct epoll_event);

  DPRINT(DEBUG_INFO, "Number of events %lu\n", header->regs.arg2); 

  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  result.extra = size;

  transfered = send_result_with_extra(fd, &result, (char *)header->regs.arg1, size);  
  if ( transfered < 0) 
      die("Recvmsg (Fstat handler)"); 

  CHECK(transfered, size + SIZE_RESULT, result.extra);
  TRUSTED_END("EPOLL_WAIT"); 
  
  return; 
}

u64_t untrusted_accept(const ucontext_t * uc ){

   struct syscall_result res; 
   char * buf = NULL;  
   size_t size =0; 
   u64_t extra =0;  
   int fd =  get_local_fd();
   u64_t cookie = get_local_tid();
   /*ssize_t  transfered = -1; */

   UNTRUSTED_START("ACCEPT");
   CLEAN_RES(&res); 

   buf = (char *)uc->uc_mcontext.gregs[REG_ARG2]; 
   size  = sizeof(socklen_t);
   extra = size; 
  
   if (send_syscall_header(uc, extra)< 0)
      die("Send syscall header"); 
  
   if (send_extra(fd, buf, size) < 0) 
     die("Failed send extra (Untrudted write)"); 

   if(receive_syscall_result(&res) < 0 )
       die("failede get_syscall_result"); 
   assert( cookie == (u64_t)res.cookie);
   
   if (res.extra){ 
      char * addr_struct =  (char *)uc->uc_mcontext.gregs[REG_ARG1]; 
      socklen_t * len = (socklen_t *)uc->uc_mcontext.gregs[REG_ARG2]; 
      *len=(socklen_t)res.extra; 
      int recv =-1; 
      if( (recv=read(fd,addr_struct,*len)) < 0 )
        die("Error receiving extra data"); 
      assert(*len == (socklen_t)recv); 
      DPRINT(DEBUG_INFO, "--- Received %d extra\n", recv); 
   }  
   UNTRUSTED_END("ACCEPT"); 
   return (u64_t)res.result; 
}

void  trusted_accept   ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  struct syscall_request request;
  ssize_t transfered =-1; 
  
  CLEAN_RES(&result); 
  CLEAN_REQ(&request); 

  TRUSTED_START("ACCEPT"); 
  
  assert(header->syscall_num == __NR_accept); 
  
  request.syscall_identifier = header->syscall_num; 
  memcpy(&request.arg0, &(header->regs), SIZE_REGISTERS); 
  
  DPRINT(DEBUG_INFO, ">>> The size of the structure is %d\n", *(socklen_t*)header->regs.arg2); 

  result.result = do_syscall(&request);
  result.cookie = header->cookie; 
  
  size_t buf_len = *(socklen_t*)header->regs.arg2; 
  result.extra = buf_len; 

  DPRINT(DEBUG_INFO, ">>> The size of the structure is %lu\n", buf_len); 

  transfered =send_result_with_extra(fd, &result, (char *)header->regs.arg1, buf_len);  
  if ( transfered < 0) 
      die("recvmsg (fstat handler)"); 
  CHECK(transfered, buf_len + SIZE_RESULT, result.extra); 
  
  TRUSTED_END("ACCEPT"); 

  return; 
}

u64_t untrusted_writev(const ucontext_t * uc) {

   struct syscall_result result; 
   char * buf = NULL;  
   size_t size =0; 
   u64_t extra =0;  
   int fd =  get_local_fd();
   ssize_t transfered =-1; 

   UNTRUSTED_START("WRITE");
   CLEAN_RES(&result); 

   buf = (char *)uc->uc_mcontext.gregs[REG_ARG1]; 
   size  = uc->uc_mcontext.gregs[REG_ARG2] * sizeof ( struct iovec);
   extra = size; 
  
   if (send_syscall_header(uc, extra)< 0)
      die("Send syscall header"); 
 
   // send iovec structures 
   if (send_extra(fd, buf, size) < 0) 
       die("Failed send extra (Untrudted writev)"); 
   
   DPRINT(DEBUG_INFO, "--- Sent iovec structures %ld\n", size); 
      // send data via wrivev
   struct iovec  *iov = ( struct iovec *) uc->uc_mcontext.gregs[REG_ARG1];
   int iovec_num      = (int) uc->uc_mcontext.gregs[REG_ARG2]; 

   if ( (transfered = writev(fd, iov, iovec_num)) < 0 )
      die("WRITEV untrusted"); 

   DPRINT(DEBUG_INFO, "--- Writev sent %ld\n", transfered); 

   if(receive_syscall_result(&result) < 0 )
       die("Failede get_syscall_result"); 

   assert((u64_t)result.cookie == get_local_tid()); 

   UNTRUSTED_END("WRITEV"); 
   return (u64_t)result.result; 
}

void  trusted_sendfile_priv   ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  ssize_t transfered =-1; 
  int source_fd =-1; 

  CLEAN_RES(&result); 

  TRUSTED_START("SENDFILE"); 
  
  assert(header->syscall_num == __NR_sendfile); 
  
  source_fd = header->regs.arg1; 
  DPRINT(DEBUG_INFO, ">>> The source fd id %d\n", source_fd);
  
  if ((transfered =sendfile(fd, source_fd, (off_t *)header->regs.arg2,header->regs.arg3)) < 0)
      die("sendfile");

  assert( (size_t)transfered == header->regs.arg3); 
  
  result.extra = transfered; 
  result.extra = transfered; 
  result.cookie = header->cookie; 
 
  send_syscall_result(fd, &result); 

  TRUSTED_END("SENDFILE"); 

  return; 
}

void  trusted_sendfile_pub   ( int fd, const struct syscall_header * header) {

  struct syscall_result result; 
  ssize_t transfered =-1; 
  int dest_fd =-1; 
  size_t size = header->regs.arg3; 
  char * buf= malloc(size); 


  CLEAN_RES(&result); 

  TRUSTED_START("SENDFILE"); 
  
  assert(header->syscall_num == __NR_sendfile); 
  
  dest_fd = header->regs.arg0;

  DPRINT(DEBUG_INFO, ">>> The destination fd id %d\n", dest_fd);
  DPRINT(DEBUG_INFO, "sendfile(%ld, %ld,  %lx, %ld)\n", header->regs.arg0,  header->regs.arg1, header->regs.arg2, header->regs.arg3); 

  if ((transfered = receive_extra(fd, buf, size)) < 0)
      die("sendfile");
  
  assert( (size_t)transfered == header->regs.arg3); 
  DPRINT(DEBUG_INFO, ">>> File recieved correctly :  %ld\n", transfered);
 
  transfered = send_extra(dest_fd, buf, size); 
  
  if (transfered  < 0) 
      die("write sendfile");

  assert( (size_t)transfered == header->regs.arg3); 
  DPRINT(DEBUG_INFO, ">>> File sent correcltly  %ld\n", transfered);
  
  result.extra = transfered; 
  result.cookie = header->cookie; 
 
  send_syscall_result(fd, &result); 

  free(buf); 

  TRUSTED_END("SENDFILE"); 
  return; 
}

u64_t untrusted_clone ( const ucontext_t * context) {

   
   char *stack = (char *)context->uc_mcontext.gregs[REG_ARG1]; 
   char *child_stack=stack; 
   void *dummy;
   struct syscall_result result; 
   struct syscall_header header; 
   ssize_t transfered=-1; 

   CLEAN_HEA(&header); 
   CLEAN_RES(&result); 

   UNTRUSTED_START("CLONE");  
   
   asm volatile( "mov %%rsp, %%rcx\n"
                 "mov %3, %%rsp\n"
                 "int $0\n"
                 "mov %%rcx, %%rsp\n"
                 : "=a"(stack), "=&c"(dummy)
                 : "a"(__NR_clone + 0xF000), "m"(stack)
                 : "memory");
 
   
    header.syscall_num = __NR_clone; 
    header.address = context->uc_mcontext.gregs[REG_PC]; 
    header.cookie  = get_local_tid(); 
    header.extra   = 0; 
    set_reg(&(header.regs), context);
    header.regs.arg1=(long)stack;

   // Setting up the context of the new thread 
   ucontext_t * uc = (struct ucontext *)stack;
    /*copy state and signal mask of the untrusted process */
   memcpy(uc, context, sizeof(struct ucontext)); 
   uc->uc_mcontext.gregs[REG_RESULT]=0; 
   uc->uc_mcontext.gregs[REG_RSP]=(long)child_stack;
  
   if ((transfered=write(get_local_fd(), &header, SIZE_HEADER)) < 0)
      die("Error sending header system call CLONE"); 
   
   assert( SIZE_HEADER == (size_t)transfered); 

   if(receive_syscall_result(&result) < 0 )
       die("Failede get_syscall_result"); 

   assert((u64_t)result.cookie == get_local_tid()); 

   UNTRUSTED_END("CLONE"); 
   return (u64_t)result.result; 

}

static void return_from_clone_syscall(void *stack) {

struct ucontext * uc =  (struct ucontext * ) stack; 
 DPRINT(DEBUG_INFO, "Clone handler, installed new stack frame at %p, RIP = 0x%lx\n", stack, (long) uc->uc_mcontext.gregs[REG_RIP]); 
 asm volatile ( "mov %0, %%rsp\n"
                "mov $15, %%rax\n"
                "syscall\n"
                : 
                : "m"(stack) 
                : "memory"
              ); 
}

static int handle_new_thread( void * stack) {
 DPRINT(DEBUG_INFO, "Handle new thread\n"); 
 create_trusted_thread(); 
 DPRINT(DEBUG_INFO, "Stack pointer %p \n", stack); 
 return_from_clone_syscall(stack);
 return 0; 
}

void trusted_clone(int fd, const struct syscall_header * header) {

  long clone_flags = (long)   header->regs.arg0; 
  char *stack      = (char *) header->regs.arg1;
  int  *pid_ptr    = (int  *) header->regs.arg2;
  int  *tid_ptr    = (int  *) header->regs.arg3;
  void *tls_info   = (void *) header->regs.arg4;
  struct syscall_result result; 

  TRUSTED_START("CLONE"); 

  result.result=clone(handle_new_thread,
                                    allocate_stack(STACK_SIZE), clone_flags,
                                    (void *)stack,pid_ptr, tls_info, tid_ptr); 

  result.cookie = header->cookie; 
  result.extra = 0; 

  if( send_syscall_result(fd, &result) < 0) 
    die("Error sending result clone system call"); 

  TRUSTED_END("CLONE"); 

}





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
