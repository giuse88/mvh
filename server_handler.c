
#include "server_handler.h"
#include "common.h"
#include <sys/syscall.h> 
#include <stdlib.h> 
#include <assert.h> 
#include <sys/types.h> 
#include <sys/socket.h>
#include "mvh_server.h" 
#include "handler.h" 
#include <pthread.h> 
#include <sys/stat.h> 
#include <sys/mman.h> 
#include "utils.h" 
#include <fcntl.h> 
#include <termios.h> 
#include <sys/ioctl.h>
#include <sys/epoll.h>

#define DEFAULT_SERVER_HANDLER server_default
struct server_handler * syscall_table_server_; 

#define SYSCALL_VERIFIED(__arg)    printf(ANSI_COLOR_GREEN "[ SERVER  ] System call %s verified!%s\n", (char *)__arg, ANSI_COLOR_RESET)
#define SYSCALL_NO_VERIFIED(__arg) printf(ANSI_COLOR_RED   "[ ALERT   ] System call %s NOT verified!%s\n", (char *)__arg, ANSI_COLOR_RESET)

#define ATTACK printf("ATTACK")


// manage fd maps 
int get_free_fd(const struct thread_group * ths) {
    for (int i=0; i < MAX_FD; i++) 
        if (ths->fd_maps[i].type == EMPTY_FD)
            return i; 
    return -1; 
}
int free_fd(struct thread_group * ths, int fd) {
    for (int i=0; i < MAX_FD; i++) 
        if (ths->fd_maps[i].fd == fd) {
          memset((void*)&ths->fd_maps[i], 0, sizeof(struct fd_info)); 
          return 0; 
        } 
    return -1; 
}
bool is_fd_public(const struct thread_group *ths, int fd) {
    for (int i=0; i < MAX_FD; i++) 
        if (ths->fd_maps[i].fd         == fd  && 
            ths->fd_maps[i].visibility == PUBLIC)
            return true; 
    return  false; 
}
bool is_fd_private(const struct thread_group *ths, int fd) {
    for (int i=0; i < MAX_FD; i++) 
        if (ths->fd_maps[i].fd         == fd  && 
            ths->fd_maps[i].visibility == PRIVATE)
            return true; 
    return  false; 
}
process_visibility get_fd_visibility(const struct thread_group * ths, int fd) {
  for (int i=0; i < MAX_FD; i++) 
        if ( ths->fd_maps[i].fd == fd) 
            return ths->fd_maps[i].visibility; 
  return -1; 
}
fd_type get_fd_type(const struct thread_group * ths, int fd, process_visibility vis) {
  for (int i=0; i < MAX_FD; i++) 
        if ( ths->fd_maps[i].fd == fd && ths->fd_maps[i].visibility == vis) 
            return ths->fd_maps[i].type; 
  return -1; 
}
int save_fd(struct thread_group * ths, int fd, fd_type type, process_visibility vis) {
    int index = get_free_fd(ths);
    if ( index < 0 )
      return -1;
    ths->fd_maps[index].fd         = fd; 
    ths->fd_maps[index].type       = type; 
    ths->fd_maps[index].visibility = vis; 
    return index; 
}
/* Useful functions */ 
void  syscall_info(const struct  syscall_header * head, const struct syscall_registers *reg, const struct  syscall_result *res, process_visibility vis) {
    static bool first = true; 
    if(first){
      printf("%-20s%-20s%-20s%-20s%-20s%-20s%-20s%-20s%-20s\n", "Cookie", "System Call", 
                                              "Arg0", "Arg1", "Arg2", 
                                              "Arg3", "Arg4", "Arg5", "Result");  
      first=false;
    }
    
    char * color = ( vis == PUBLIC ) ? ANSI_COLOR_GREEN : ANSI_COLOR_RED; 
    color = ""; 

    printf( "%s%-20d%-20s%-20lx%-20lx%-20lx%-20lx%-20lx%-20lx%-20ld%s\n", color, head->cookie,
             syscall_names[head->syscall_num], 
             reg->arg0,  reg->arg1,reg->arg2, reg->arg3,  reg->arg4, reg->arg5, (long int)res->result,ANSI_COLOR_RESET); 
}
int forward_syscall_request ( int fd, const struct syscall_header * header) {

    struct msghdr msg; 
    struct iovec io[1];
    int sent=-1; 

    CLEAN_MSG(&msg);     

    io[0].iov_len=SIZE_HEADER; 
    io[0].iov_base= (char *)header; 

    msg.msg_iov=io; 
    msg.msg_iovlen=1; 
    sent=sendmsg(fd, &msg, 0); 

    if ( sent < 0) 
        die("Sendmsg (Forward_syscall_request)"); 

    assert(sent == (SIZE_HEADER)); 
    return sent; 

}
int forward_syscall_result ( int fd, const struct syscall_result * result) {

    struct msghdr msg; 
    struct iovec io[1];
    int sent=-1; 

    CLEAN_MSG(&msg);     

    io[0].iov_len=SIZE_RESULT; 
    io[0].iov_base= (char *)result; 
    msg.msg_iov=io; 
    msg.msg_iovlen=2; 
    sent=sendmsg(fd, &msg, 0); 
    if ( sent < 0) 
        die("Sendmsg (Forward_syscall_request)"); 

    assert(sent == (SIZE_RESULT)); 
    return sent; 

}
int receive_syscall_registers ( int fd, struct syscall_registers * regs){
    struct iovec io[IOV_DEFAULT];
    struct msghdr msg; 
    int received =-1; 

    memset(&msg, 0, sizeof(msg)); 

    io[REG].iov_len=SIZE_REGISTERS; 
    io[REG].iov_base=regs; 
 
    msg.msg_iov=io; 
    msg.msg_iovlen=IOV_DEFAULT; 
    received = recvmsg(fd,&msg, 0); 
    
    assert(received == SIZE_REGISTERS); 
   
    if ( received < 0) 
        die("Sendmsg (Forward_syscall_request)"); 
   
    return received; 
}
int receive_syscall_result( int fd, struct syscall_result * res) {

    struct iovec io[IOV_DEFAULT];
    struct msghdr msg; 
    int received =-1; 

    memset(&msg, 0, sizeof(msg)); 

    io[REG].iov_len=SIZE_RESULT; 
    io[REG].iov_base=res; 
 
    msg.msg_iov=io; 
    msg.msg_iovlen=IOV_DEFAULT; 
    received = recvmsg(fd,&msg, 0); 
    
    if ( received < 0) 
        die("Sendmsg (Forward_syscall_request)"); 
   
    assert(received == SIZE_RESULT); 
    return received; 

}
int receive_syscall_result_async( int fd, struct syscall_result * res) {

    struct iovec io[IOV_DEFAULT];
    struct msghdr msg; 
    int received =-1; 

    memset(&msg, 0, sizeof(msg)); 

    io[REG].iov_len=SIZE_RESULT; 
    io[REG].iov_base=res; 
    msg.msg_iov=io; 
    msg.msg_iovlen=IOV_DEFAULT; 
    
    ASYNC_CALL(recvmsg(fd,&msg, 0), received); 
    if ( received < 0) 
        die("Sendmsg (Forward_syscall_request)"); 
   
    assert(received == SIZE_RESULT); 
    return received; 

}
int get_extra_argument (int public, int private, char * public_path, char * private_path, int len) {
    struct iovec io_pub[1], io_priv[1]; 
    struct msghdr msg_pub, msg_priv;
    int res_pub = -1, res_priv = -1;  

    CLEAN_MSG(&msg_pub); 
    CLEAN_MSG(&msg_priv); 
    
    // pub
    io_pub[0].iov_len=len; 
    io_pub[0].iov_base=public_path;  
    msg_pub.msg_iov=io_pub; 
    msg_pub.msg_iovlen=1; 
    // priv
    io_priv[0].iov_len=len; 
    io_priv[0].iov_base=private_path;  
    msg_priv.msg_iov=io_priv; 
    msg_priv.msg_iovlen=1; 
  
    // it waits until there is data ( active wait) 
    ASYNC_CALL(recvmsg(public,&msg_pub, 0), res_pub);   
    if(res_pub < 0) 
        die("Async recvms extra argument"); 
    assert(res_pub == len);
    ASYNC_CALL(recvmsg(private,&msg_priv, 0), res_priv); 
    if(res_priv < 0) 
        die("Async recvms extra argument"); 
    assert(res_priv == len); 

    return SUCCESS; 
}


/******************************************************** EXECUTION FUNCTIONS *********************************************/ 

void execution_single_variant_with_extra(struct thread_group * ths, const struct syscall_header * variant , struct syscall_result * result,  size_t size, process_visibility vis){

    ssize_t transfered =-1; 
    char * buf = malloc(size);

   int performer_thread_trusted;      
   int performer_thread_untrusted; 
   int performer_thread_cookie; 
   int receiver_thread_cookie; 
   int receiver_thread_untrusted; 
    
   if ( vis == PRIVATE) {
       performer_thread_trusted   = ths->fds[PRIVATE_TRUSTED]; 
       performer_thread_untrusted = ths->fds[PRIVATE_UNTRUSTED]; 
       performer_thread_cookie    = ths->private.cookie;
       receiver_thread_cookie     = ths->public.cookie; 
       receiver_thread_untrusted  = ths->fds[PUBLIC_UNTRUSTED];
   } else if ( vis == PUBLIC)  {
     performer_thread_trusted     = ths->fds[PUBLIC_TRUSTED]; 
     performer_thread_untrusted   = ths->fds[PUBLIC_UNTRUSTED]; 
     performer_thread_cookie      = ths->public.cookie; 
     receiver_thread_cookie       = ths->private.cookie; 
     receiver_thread_untrusted    = ths->fds[PRIVATE_UNTRUSTED];
  } else 
    irreversible_error("Specified wrong visibility"); 
              

    CLEAN_RES(result);

    // sends the request to the thread which will perform the system call 
    if(forward_syscall_request(performer_thread_trusted, variant) < 0)
            die("Failed send request to trusted thread");

    //receive result with extra 
    if ( (transfered=receive_result_with_extra(performer_thread_trusted, result, buf, size)) < 0) 
        die("Error receiving result from the truste thread"); 
   
   result->cookie = receiver_thread_cookie;
   if((transfered=send_result_with_extra(receiver_thread_untrusted, result, buf, size)) < 0)
       die("Failed sending result (READ)"); 
   CHECK(transfered, size + SIZE_RESULT, result->extra);  
 
   result->cookie = performer_thread_cookie;
   result->extra  = 0;
   // send results to the untrusted thread private  
   if(forward_syscall_result(performer_thread_untrusted, result) < 0)
       die("Failed send request public trusted thread");

    CHECK(transfered, size + SIZE_RESULT, result->extra); 
    free(buf); 
    return; 
}

void  execution_public_variant_with_extra(struct thread_group * ths, const struct syscall_header * public,  struct syscall_result * result, size_t size){
  execution_single_variant_with_extra(ths, public, result, size, PUBLIC);  
}

void  execution_private_variant_with_extra(struct thread_group * ths, const struct syscall_header * private,  struct syscall_result * result, size_t size){
  execution_single_variant_with_extra(ths, private, result,size,  PRIVATE);  
}


void execution_single_variant(struct thread_group * ths, const struct syscall_header * variant , struct syscall_result * result, process_visibility vis){

   int performer_thread_trusted;      
   int performer_thread_untrusted; 
   int performer_thread_cookie; 
   int receiver_thread_cookie; 
   int receiver_thread_untrusted; 
    
   if ( vis == PRIVATE) {
       performer_thread_trusted   = ths->fds[PRIVATE_TRUSTED]; 
       performer_thread_untrusted = ths->fds[PRIVATE_UNTRUSTED]; 
       performer_thread_cookie    = ths->private.cookie;
       receiver_thread_cookie     = ths->public.cookie; 
       receiver_thread_untrusted  = ths->fds[PUBLIC_UNTRUSTED];
   } else if ( vis == PUBLIC) {
     performer_thread_trusted     = ths->fds[PUBLIC_TRUSTED]; 
     performer_thread_untrusted   = ths->fds[PUBLIC_UNTRUSTED]; 
     performer_thread_cookie      = ths->public.cookie; 
     receiver_thread_cookie       = ths->private.cookie; 
     receiver_thread_untrusted    = ths->fds[PRIVATE_UNTRUSTED];
  } else 
    irreversible_error("Specify wrong visibility"); 
              
   CLEAN_RES(result);

   if(forward_syscall_request(performer_thread_trusted, variant) < 0)
            die("Failed send request to trusted thread");

   if ( receive_syscall_result_async(performer_thread_trusted, result) < 0) 
        die("Error receiving result from the truste thread"); 
   
   result->extra  = 0;
   
   result->cookie = receiver_thread_cookie;
   if(forward_syscall_result(receiver_thread_untrusted, result) < 0)
       die("Failed sending result (READ)"); 
 
   result->cookie = performer_thread_cookie;
   if(forward_syscall_result(performer_thread_untrusted, result) < 0)
       die("Failed send request public trusted thread");

    return; 
}

 void  execution_public_variant(struct thread_group * ths, const struct syscall_header * public,  struct syscall_result * result){
  execution_single_variant(ths, public, result, PUBLIC);  
}

 void  execution_private_variant(struct thread_group * ths, const struct syscall_header * private,  struct syscall_result * result){
  execution_single_variant(ths, private, result, PRIVATE);  
}

/****************************************************************************************************************************/ 

/*************************** HANDLERS ******************************/ 
void server_default ( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) { 
 
    struct syscall_result public_result, private_result; 
/*    bool pub_res=false; */
    /*bool priv_res=false; */
    /*int res =-1; */

    DPRINT(DEBUG_INFO, "Server default handler for system call <%s>\n", syscall_names[public->syscall_num]);
   
    /* 
     * = Read from the untrusted sock to collect a request
     * = Send the request to the trusted therad 
     * = Read the result from the trusted thread 
     * = Send back the result to the untrusted trusted
     */ 
 
    if(forward_syscall_request(ths->fds[PUBLIC_TRUSTED], public) < 0)
            die("failed send request public trusted thread");
    if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
            die("failed send request public trusted thread");
     
    DPRINT(DEBUG_INFO, "Forwarded system call requests to the respective thread\n"); 
   
    receive_syscall_result(ths->fds[PUBLIC_TRUSTED], &public_result); 
    DPRINT(DEBUG_INFO, "Received result for %d from %d over %d\n",
        public_result.cookie, ths->public.trusted.tid, ths->fds[PUBLIC_TRUSTED]);

    receive_syscall_result(ths->fds[PRIVATE_TRUSTED], &private_result);
    DPRINT(DEBUG_INFO, "Received result for %d from %d over %d\n",
        private_result.cookie, ths->private.trusted.tid,ths->fds[PRIVATE_TRUSTED]);

    assert(public->cookie == public_result.cookie); 
    assert(private->cookie == private_result.cookie); 
    
    syscall_info(public, &public->regs,  &public_result, PUBLIC); 
    syscall_info(private,&private->regs, &private_result, PRIVATE); 
    
    if(forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], &public_result) < 0)
        die("Failed send request public trusted thread");
    if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &private_result) < 0)
        die("Failed send request public trusted thread");
   
    return; 
}

void server_open ( struct thread_group* ths, const struct syscall_header * public , const struct syscall_header * private) {

   char * public_path = NULL,* private_path = NULL; 
   int length =-1; 
   struct syscall_result result; 
   ssize_t transfered =-1; 

   CLEAN_RES(&result); 
 
   assert( public->syscall_num == __NR_open && private->syscall_num == __NR_open); 
   assert( public->extra == private->extra); 
   
   length = public->extra; 
   public_path = calloc(length, 1); 
   private_path = calloc(length, 1); 

   transfered = get_extra_arguments(ths->fds[PUBLIC_UNTRUSTED],public_path,
                  ths->fds[PRIVATE_UNTRUSTED], private_path, length);
   
   if (!strncmp(private_path, public_path, length) &&
       public->regs.arg1 == private->regs.arg1)
       SYSCALL_VERIFIED("OPEN"); 
   else 
       SYSCALL_NO_VERIFIED("OPEN"); 
 
  execution_private_variant(ths, private, &result);  

  int index = get_free_fd(ths); 
  if (index < 0)
    irreversible_error("FD space full"); 
  
  ths->fd_maps[index].fd         = (int)result.result; 
  ths->fd_maps[index].type       = FILE_FD; 
  ths->fd_maps[index].visibility = PRIVATE; 
  DPRINT(DEBUG_INFO, "Added file descriptor %d to the private list\n", ths->fd_maps[index].fd);

  printf("[ PUBLIC  ] open(\"%s\"(%ld), 0x%lX) = %ld\n", public_path,  transfered, public->regs.arg1 , result.result); 
  printf("[ PRIVATE ] open(\"%s\"(%ld), 0x%lX) = %ld\n", private_path, transfered, private->regs.arg1, result.result); 

  free(public_path);
  free(private_path); 

  return; 
} 

void server_fstat ( struct thread_group* ths, const struct syscall_header * public , const struct syscall_header * private){

    struct syscall_result result; 
    struct stat res_fstat;

    assert( public->syscall_num == __NR_fstat  && private->syscall_num == __NR_fstat);  

    if ( public->regs.arg0 == private->regs.arg0) 
        SYSCALL_VERIFIED("FSTAT"); 
    else 
        SYSCALL_NO_VERIFIED("FSTAT"); 

   if(IS_STD_FD(public->regs.arg0) && IS_STD_FD(private->regs.arg0)) {
         DPRINT(DEBUG_INFO, "FSTAT called with default file descriptor\n"); 
         server_default(ths, public, private);
         return;
   } 

    CLEAN_RES(&result); 
    RESET(&res_fstat,sizeof(res_fstat));

    execution_private_variant_with_extra(ths, private, &result, sizeof( struct stat));  
    
    printf("[ PUBLIC  ] fstat(%ld, 0x%lX) = %ld\n", public->regs.arg0,   public->regs.arg1, result.result); 
    printf("[ PRIVATE ] fstat(%ld, 0x%lX) = %ld\n", private->regs.arg0, private->regs.arg1, result.result); 

    return; 
}

void server_mmap ( struct thread_group* ths, const struct syscall_header * public , const struct syscall_header * private) {

   struct syscall_result public_result, private_result; 
   short unsigned flags= 0;
   struct syscall_header * public_no_const = NULL; 
   char *buf= NULL;
   int map_size=-1;
   
   DPRINT(DEBUG_INFO, "MMPA SYSTEM CALL\n"); 
    /* Actions :
     * check if the system call is a file mapping or not 
     * if it is not a file mapping call the default behaviour
     * if it it a file mapping allow it in the private version,
     *            remove the fd descriptor in the public version 
     *
     * Save the result 
     * send back the result to the untrusted threads 
     */ 
  
   CLEAN_RES(&public_result); 
   CLEAN_RES(&private_result); 

   // sanity checks 
   assert( public->syscall_num == __NR_mmap && private->syscall_num == __NR_mmap);
   
   if ( (public->regs.arg1 == private->regs.arg1) &&  
        (public->regs.arg2 == private->regs.arg2) &&  
        (public->regs.arg3 == private->regs.arg3) &&
        (public->regs.arg4 == private->regs.arg4) &&
        (public->regs.arg5 == private->regs.arg5)) 
    SYSCALL_VERIFIED("MMAP"); 
   else 
    SYSCALL_NO_VERIFIED("MMAP");
    
   map_size = public->regs.arg1; 
   flags= public->regs.arg3; 
   // MAP_ANONYMOUS 0x20 00100000
   // MAP_ANO == MAP_ANONIMOUS 
   if (flags & MAP_ANONYMOUS) { 
      DPRINT(DEBUG_INFO, "MMAP called with MAP_ANONYMOUS. Default behaviour\n");         
      server_default(ths,  public, private); 
      return; 
   } 
  
  DPRINT(DEBUG_INFO, "MMAP invoked for mapping a file\n");         
  
  // I cannot allow  the public process to map a file in memory 
  flags |=  MAP_ANONYMOUS;

  buf = malloc( map_size ); 
  if (!buf) 
      die("Malloc failed mmap"); 

  // Ugly but it avoids to change the handlers interface 
  public_no_const = (void *)public; 
  public_no_const->regs.arg3  = flags;
  // The page must be writable because it is filled out with the 
  // content received from the server 
  public_no_const->regs.arg2 |= PROT_WRITE; 
  public_no_const->regs.arg4  = -1; 
  public_no_const->regs.arg5  = 0; 

  if(forward_syscall_request(ths->fds[PUBLIC_TRUSTED], public) < 0)
            die("failed send request public trusted thread");
 
  if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
           die("failed send request public trusted thread");

  // get system call results for mapping a generic area
  if(receive_syscall_result_async(ths->fds[PUBLIC_TRUSTED], &public_result) < 0)  
            die("failed receive system call result"); 
  
  
  // receive the result along with the entire file 
  // this can be quite problematic
  int    transfered=-1;
  size_t file_size =0;

  if(receive_syscall_result_async(ths->fds[PRIVATE_TRUSTED], &private_result) < 0) 
        die("Failed receiving result\n"); 
  file_size = private_result.extra; 
  if ((transfered = receive_extra(ths->fds[PRIVATE_TRUSTED], buf, file_size)) < 0)
      die("Receive extra FILE"); 
  
  printf(" Transfered %d, File %lu\n", transfered, file_size); 
  assert((unsigned long)transfered == private_result.extra ); 
  DPRINT(DEBUG_INFO, "File received correctly size %d\n", transfered);
  
  // unfortunately I cannot send the file along with the result because
  // I don't know the mapping address and I cannot neither call malloc
  // to allocate a temporary storage area. 
  public_result.extra = private_result.extra; 

  // send the result to the untrusted   
  if(forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], &public_result) < 0)
      die("Failed forwarding result with extra  to the public thread\n"); 
  // send file
  send_extra(ths->fds[PUBLIC_UNTRUSTED], buf, file_size);

  // send the result header to the trusted thread 
  if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &private_result) < 0)
        die("Failed forwarding result to the private thread\n"); 
 
  printf("[ PUBLIC  ] mmap(%ld, %ld, 0x%lx, 0x%lx, %ld, %ld) = 0x%lX\n", public->regs.arg0, public->regs.arg1,
                                                                   public->regs.arg2, public->regs.arg3,
                                                                   public->regs.arg4, public->regs.arg5,
                                                                   public_result.result); 
  printf("[ PRIVATE ] mmap(%ld, %ld, 0x%lx, 0x%lx, %ld, %ld) = 0x%lX\n", private->regs.arg0, private->regs.arg1,
                                                                   private->regs.arg2, private->regs.arg3,
                                                                   private->regs.arg4, private->regs.arg5,
                                                                   private_result.result); 
 
  free(buf); 

  return; 
}

void server_close ( struct thread_group* ths, const struct syscall_header * public , const struct syscall_header * private){

   struct syscall_result result; 

   CLEAN_RES(&result); 
  
   assert( public->syscall_num == __NR_close && private->syscall_num == __NR_close);
 
   if ( public->regs.arg0 == private->regs.arg0) 
        SYSCALL_VERIFIED("CLOSE"); 
   else 
        SYSCALL_NO_VERIFIED("CLOSE"); 
 
   if ( IS_STD_FD(public->regs.arg0)) {
       DPRINT(DEBUG_INFO, "CLOSE invoked with default file descriptor\n"); 
      
       result.cookie = public->cookie; 
       forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], &result); 
       
       result.cookie = private->cookie; 
       forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &result); 
       
       printf("[ PUBLIC  ] close(%ld) = %ld (SKIPPED)\n", public->regs.arg0, result.result); 
       printf("[ PRIVATE ] close(%ld) = %ld (SKIPPED)\n", private->regs.arg0,result.result); 
       return;
   } 

  if (get_fd_visibility(ths, public->regs.arg0) == PUBLIC)
    execution_public_variant(ths, public,  &result);  
  else 
    execution_private_variant(ths, private, &result); 

  if (free_fd(ths, public->regs.arg0) < 0)
    DPRINT(DEBUG_INFO, "Failed removing %d fd\n", (int)public->regs.arg0); 

    DPRINT(DEBUG_INFO, "%d fd has been removed \n", (int)public->regs.arg0); 

  printf("[ PUBLIC  ] close(%ld) = %ld\n", public->regs.arg0, result.result); 
  printf("[ PRIVATE ] close(%ld) = %ld\n", private->regs.arg0,result.result); 
  return; 
}

void server_openat ( struct thread_group* ths, const struct syscall_header * public , const struct syscall_header * private) {

    char * public_path = NULL,* private_path = NULL; 
    int length =-1; 
    struct syscall_result result; 
    ssize_t transfered =-1; 

   CLEAN_RES(&result); 

   assert( public->syscall_num == __NR_openat && private->syscall_num == __NR_openat); 
   assert( public->extra == private->extra); 
   
   length = public->extra; 
   public_path = malloc(length); 
   private_path = malloc(length); 

   transfered = get_extra_arguments(ths->fds[PUBLIC_UNTRUSTED],public_path,
                  ths->fds[PRIVATE_UNTRUSTED], private_path, length);
   
   if (!strncmp(private_path, public_path, length) &&
       (public->regs.arg2 == private->regs.arg2) && 
       (public->regs.arg0 == private->regs.arg0))
       SYSCALL_VERIFIED("OPENAT");
   else 
       SYSCALL_NO_VERIFIED("OPENAT");

  execution_private_variant(ths, private, &result);  

  int index = get_free_fd(ths); 
  if (index < 0)
    irreversible_error("FD space full"); 
 
  ths->fd_maps[index].fd         = (int)result.result; 
  ths->fd_maps[index].type       = FILE_FD; 
  ths->fd_maps[index].visibility = PRIVATE; 

  DPRINT(DEBUG_INFO, "Added file descriptor %d to the private list\n",  ths->fd_maps[index].fd);

  printf("[ PUBLIC  ] openat(%lx, \"%s\"(%u), %lx) = %ld\n", public->regs.arg0, public_path,
      (unsigned)transfered,  public->regs.arg2, result.result); 
  printf("[ PRIVATE ] openat(%lx, \"%s\"(%u), %lx) = %ld\n", private->regs.arg0, private_path, 
      (unsigned)transfered, private->regs.arg2, result.result); 

  free(public_path);
  free(private_path); 

  return; 
}

void server_exit_group ( struct thread_group* ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result public_result, private_result; 
    
    DPRINT(DEBUG_INFO, "Start EXIT_GROUP handler\n"); 

    CLEAN_RES(&public_result); 
    CLEAN_RES(&private_result); 

    assert( public->syscall_num == __NR_exit_group  && private->syscall_num == __NR_exit_group); 
    // reading from the standard input
    if ( public->regs.arg0 == private->regs.arg0) 
         SYSCALL_VERIFIED("EXIT GROUP");
    else 
         SYSCALL_NO_VERIFIED("EXIT GROUP"); 

    // sends the request to the private application 
    if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
            die("failed send request public trusted thread");
   
    // sends the request to the public trusted thread  
    if(forward_syscall_request(ths->fds[PUBLIC_TRUSTED], public) < 0)
            die("failed send request public trusted thread");

    if(receive_syscall_result_async(ths->fds[PUBLIC_TRUSTED], &public_result) < 0)
           die("Failed receiving resutl from public trusted"); 

    if(receive_syscall_result_async(ths->fds[PRIVATE_TRUSTED], &private_result) < 0)
           die("Failed receiving resutl from public trusted"); 

    printf("[ PUBLIC  ] exit_group(%ld) = %ld\n", public->regs.arg0, public_result.result); 
    printf("[ PRIVATE ] exit_group(%ld) = %ld\n", private->regs.arg0, private_result.result); 

    for ( int i=0; i< NFDS; i++)
        close(ths->fds[i]); 
   
    // free position 
    free(ths); 
    pthread_exit(NULL); 

}

void server_read ( struct thread_group* ths, const struct syscall_header * public , const struct syscall_header * private){

    struct syscall_result result; 
    size_t size=0; 

    DPRINT(DEBUG_INFO, "Start read handler\n"); 

    // sanity checks 
    assert( public->syscall_num == __NR_read  && private->syscall_num == __NR_read); 
    
    // reading from the standard input
    if ((public->regs.arg0 == private->regs.arg0) && 
         (public->regs.arg2 == private->regs.arg2))
       SYSCALL_VERIFIED("READ"); 
    else 
       SYSCALL_NO_VERIFIED("READ"); 
         
    if (IS_STD_FD(public->regs.arg0)) {   
         DPRINT(DEBUG_INFO, "READ invoked with default file descriptor\n"); 
         server_default(ths, public, private);
         return;
    } 
        
    CLEAN_RES(&result);
    size = public->regs.arg2; 
 
    if (is_fd_private(ths, public->regs.arg0)){
      DPRINT(DEBUG_INFO, "Call executed in the private variant\n");
      execution_private_variant_with_extra(ths, private, &result, size);  
   } else {
      DPRINT(DEBUG_INFO, "Call executed in the public variant\n");
      assert(is_fd_public(ths, public->regs.arg0) && !is_fd_private(ths, public->regs.arg0));
      execution_public_variant_with_extra(ths, public, &result,size); 
   }

 

    printf("[ PUBLIC  ] read(%ld, 0x%lx, 0x%lx) = %ld\n", public->regs.arg0,  public->regs.arg1,  public->regs.arg2,  result.result); 
    printf("[ PRIVATE ] read(%ld, 0x%lx, 0x%lx) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); 

    return; 
}

void server_getdents ( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private){

    struct  syscall_result result; 
   
    DPRINT(DEBUG_INFO, "Start GETDENTS handler\n"); 

    // sanity checks 
    assert( public->syscall_num == __NR_getdents  && private->syscall_num == __NR_getdents); 
    
    if ((public->regs.arg0 == private->regs.arg0) &&
        (public->regs.arg2 == private->regs.arg2))  
        SYSCALL_VERIFIED("GETDENTS");
    else 
        SYSCALL_NO_VERIFIED("GETDENTS"); 

    CLEAN_RES(&result); 
   
    execution_private_variant_with_extra(ths, private, &result, public->regs.arg2);  

    printf("[ PUBLIC  ] getdents(%ld, 0x%lx, 0x%lx) = %ld\n", public->regs.arg0,  public->regs.arg1,  public->regs.arg2,  result.result); 
    printf("[ PRIVATE ] getdents(%ld, 0x%lx, 0x%lx) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); 

    return; 
}

void server_write ( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 
    char *private_buf =NULL, *public_buf=NULL;
    size_t size =0; 
    bool buffer_match = false; 

    DPRINT(DEBUG_INFO, "WRITE SYSTEM CALL\n"); 

    CLEAN_RES(&result); 

    assert( public->syscall_num == __NR_write && private->syscall_num == __NR_write); 
    assert ( public->regs.arg2 == private->regs.arg2); 

    size = public->regs.arg2; 
    public_buf   = malloc(size); 
    private_buf  = malloc(size); 

    get_extra_arguments(ths->fds[PUBLIC_UNTRUSTED],public_buf, ths->fds[PRIVATE_UNTRUSTED], private_buf, size); 
    
    buffer_match = memcmp(public_buf, private_buf, size)? false : true; 

    if ( public->regs.arg0 == private->regs.arg0 &&  buffer_match &&
         public->regs.arg2 == private->regs.arg2 ) 
        SYSCALL_VERIFIED("WRITE"); 
    else {
        SYSCALL_NO_VERIFIED("WRITE"); 
        puts("Public buffer : ");
        puts(public_buf);
        puts("Private buffer : ");
        puts(private_buf);
    }
   if(IS_STD_FD(public->regs.arg0) && IS_STD_FD(private->regs.arg0)) {
         DPRINT(DEBUG_INFO, "WRITE called with default file descriptor\n"); 
         server_default(ths, public, private);
         return;
   } 

   if (is_fd_private(ths, public->regs.arg0)){
      execution_private_variant(ths, private, &result);  
   } else {
      assert(is_fd_public(ths, public->regs.arg0));
      execution_public_variant(ths, public, &result); 
   }

    printf("[ PUBLIC  ] write(%ld, %lx, %ld) = %ld\n", public->regs.arg0,  public->regs.arg1, private->regs.arg2, result.result); 
    printf("[ PRIVATE ] write(%ld, %lx, %ld) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); 

    free(private_buf); 
    free(public_buf); 

    return; 
}

bool verify_ioctl( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private, char * public_buf, char * private_buf) {
    
    bool fd=false, command = false, buffer=false;

    // verify FIRST ARGUMENT FD 
    if (public->regs.arg0 == private->regs.arg0) 
           fd= true; 
  
    if ( public->regs.arg1 == private->regs.arg1)
         command = true;

    if (!public_buf && !private_buf) 
        buffer=true; 
    else { 
          // compare the buffer. the size of the buffer can be retrivied from the 
          // comnand type
         buffer=false;
    }
    
    return fd && command && buffer; 
} 

#define OUTPUT 0x01
#define INPUT  0x02
#define IO     0x03
#define MORE   0x04

unsigned short get_ioctl_mode( unsigned command ) {

  switch (command) {
    case  TCGETS:
    case  FIONREAD : 
    case  TIOCGWINSZ:
        return OUTPUT; 
    }
  
  return -1; 
} 

void server_ioctl ( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result;
    bool check=true; 
  
    char * private_buffer=NULL, *public_buffer=NULL; 

    DPRINT(DEBUG_INFO, "Start IOCTL handler\n"); 
    assert( public->syscall_num == __NR_ioctl  && private->syscall_num == __NR_ioctl); 
    
    unsigned short mode=get_ioctl_mode(private->regs.arg1); 

    if ( mode & INPUT) {
    // GET INPUT ARGUMENT 
    // LIGHTHTTP uses the IOCTL with output variables 
    }

    check=verify_ioctl(ths, public, private, private_buffer,public_buffer); 

    if (check) 
        SYSCALL_VERIFIED("IOCTL"); 
    else 
        SYSCALL_NO_VERIFIED("IOCTL"); 
    
    if (IS_STD_FD(public->regs.arg0) && IS_STD_FD(private->regs.arg0)) {
         DPRINT(DEBUG_INFO,"IOCTL called over a standard descriptor");
         server_default(ths, public, private);
         return;
    } 
    
    CLEAN_RES(&result); 
  
    int fd = public->regs.arg0; 
    const struct syscall_header *request =  is_fd_public(ths, fd) ? public : private; 
    process_visibility visibility =   is_fd_public(ths, fd) ? PUBLIC: PRIVATE; 

    if ( mode & OUTPUT) {
        size_t size_comand = get_size_from_cmd(request->regs.arg1); 
        execution_single_variant_with_extra(ths, request, &result, size_comand, visibility); 
    }
    else 
        execution_single_variant(ths, request, &result, visibility);  

    printf("[ PUBLIC  ] ioclt(%ld, %lx, %lx) = %ld\n", public->regs.arg0,  public->regs.arg1, public->regs.arg2, result.result); 
    printf("[ PRIVATE ] ioctl(%ld, %lx, %lx) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); 

    return; 
}

void server_munmap( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {


    /*printf("[ PUBLIC  ] write(%ld, %lx, %ld) = %ld\n", public->regs.arg0,  public->regs.arg1, private->regs.arg2, result.result); */
    /*printf("[ PRIVATE ] write(%ld, %lx, %ld) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); */

    /*return; */
}
 
void server_getpid( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

 
    struct syscall_result private_result, public_result; 
    
    CLEAN_RES(&private_result); 
    CLEAN_RES(&public_result);

    if (private->syscall_num ==  __NR_getpid && public->syscall_num == __NR_getpid )
        SYSCALL_VERIFIED("GETPID"); 
    else 
        SYSCALL_NO_VERIFIED("GETPID"); 


    private_result.result = ths->private.untrusted.pid; 
    private_result.cookie = private->cookie; 
    private_result.extra = 0; 
   
    public_result.result = ths->private.untrusted.pid; 
    public_result.cookie = public->cookie; 
    public_result.extra = 0; 
  
    if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &private_result) < 0)
        die("Failed send request private untrusted thread");

    if(forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], &public_result) < 0)
        die("Failed send request public untrusted thread");

    printf("[ PUBLIC  ] getpid() = %ld\n", public_result.result); 
    printf("[ PRIVATE ] getpid() = %ld\n", private_result.result); 

    return; 
}

/*void execution_private_variant(struct thread_group * ths, const struct syscall_header * public, const struct syscall_header * private, */
                                     /*struct syscall_result * result){*/

    /*CLEAN_RES(result);*/

    /*// sends the request to the private application */
    /*if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)*/
            /*die("failed send request public trusted thread");*/

    /*//receive result with extra */
    /*if ( (receive_syscall_result_async(ths->fds[PRIVATE_TRUSTED], result)) < 0) */
        /*die("Error receiving result(READ)"); */

    /*result->extra = 0; */
   /*// send results to the untrusted thread private  */
    /*if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], result) < 0)*/
        /*die("Failed send request public trusted thread");*/

    /*result->cookie = public->cookie;*/
    /*// send results to the untrusted thread private  */
    /*if(forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], result) < 0)*/
        /*die("Failed send request public trusted thread");*/
  
    /*return; */
/*}*/



void server_getcwd( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 

    if ( public->regs.arg1 == private->regs.arg1)
        SYSCALL_VERIFIED("GETCWD"); 
    else 
        SYSCALL_NO_VERIFIED("GETCWD"); 

    execution_private_variant_with_extra(ths, private, &result, public->regs.arg1);  

    printf("[ PUBLIC  ] getcwd(%lx, %ld) = %ld\n", public->regs.arg0,  public->regs.arg1,  result.result); 
    printf("[ PRIVATE ] getcwd(%lx, %ld) = %ld\n", private->regs.arg0, private->regs.arg1, result.result); 

    return; 
}

void server_getuid( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 

    if ( public->syscall_num == __NR_getuid && private->syscall_num== __NR_getuid)
        SYSCALL_VERIFIED("GETUID"); 
    else 
        SYSCALL_NO_VERIFIED("GETUID"); 

    execution_private_variant(ths, private, &result);  
    
    printf("[ PUBLIC  ] getuid() = %ld\n", result.result); 
    printf("[ PRIVATE ] getuid() = %ld\n", result.result); 

    return; 
}

void server_stat( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 
    struct stat  buffer_stat; 
    char *private_buf =NULL, *public_buf=NULL;
    size_t size =0; 

    DPRINT(DEBUG_INFO, " STAT\n"); 

    RESET(&buffer_stat, sizeof(struct stat)); 
    CLEAN_RES(&result); 

    assert( public->syscall_num == __NR_stat && private->syscall_num == __NR_stat); 
    assert( public->extra == private->extra); 

    size = public->extra; 
    public_buf   = calloc(size, 1); 
    private_buf  = calloc(size, 1);
    get_extra_arguments(ths->fds[PUBLIC_UNTRUSTED],public_buf, ths->fds[PRIVATE_UNTRUSTED], private_buf, size); 

    if (!strncmp(public_buf, private_buf, size))
        SYSCALL_VERIFIED("STAT"); 
    else 
        SYSCALL_NO_VERIFIED("STAT"); 

    execution_private_variant_with_extra(ths, private, &result, sizeof( struct stat));  

    printf("[ PUBLIC  ] stat(%s, 0x%lx) = %ld\n", public_buf,  public->regs.arg0,  result.result); 
    printf("[ PRIVATE ] stat(%s, 0x%lx) = %ld\n", private_buf, private->regs.arg0, result.result); 

    free(public_buf); 
    free(private_buf);

    return; 
}

void server_lseek( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 

    assert(public->syscall_num == private->syscall_num); 

    if ( (public->regs.arg0 == private->regs.arg0) && 
         (public->regs.arg1 == private->regs.arg1) &&
         (public->regs.arg2 == private->regs.arg2) )
        SYSCALL_VERIFIED(" LSEEK"); 
    else 
        SYSCALL_NO_VERIFIED("LSEEK"); 

    assert(is_fd_private(ths, public->regs.arg0)); 
    execution_private_variant(ths, private, &result);  

    printf("[ public  ] lseek(%ld, %lx, %lx) = %ld\n", public->regs.arg0,  public->regs.arg1, private->regs.arg2, result.result); 
    printf("[ private ] lseek(%ld, %lx, %lx) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); 

    return; 
}

// Easy version of the fcntl 
void server_fcntl( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 
    int fd; 

    assert(public->syscall_num  == __NR_fcntl && 
           private->syscall_num == __NR_fcntl); 

    if ( (public->regs.arg0 == private->regs.arg0) && 
         (public->regs.arg1 == private->regs.arg1) &&
         (public->regs.arg2 == private->regs.arg2) )
        SYSCALL_VERIFIED("FCNTL"); 
    else 
        SYSCALL_NO_VERIFIED("FCNTL"); 

    fd = private->regs.arg0; 
    printf("FD : %d %d\n", fd, is_fd_public(ths, fd)); 

    if (is_fd_public(ths, fd)){
      execution_public_variant(ths, public, &result); 
    } else {
      assert(is_fd_private(ths, fd)); 
      execution_private_variant(ths,private, &result);  
    }

    printf("[ public  ] fcntl(%ld, %lx, %lx) = %ld\n", public->regs.arg0,  public->regs.arg1, private->regs.arg2, result.result); 
    printf("[ private ] fcntl(%ld, %lx, %lx) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); 

    return; 
}

void server_socket( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 

    assert(public->syscall_num  == __NR_socket && 
           private->syscall_num == __NR_socket); 

    if ( (public->regs.arg0 == private->regs.arg0) && 
         (public->regs.arg1 == private->regs.arg1) &&
         (public->regs.arg2 == private->regs.arg2) )
        SYSCALL_VERIFIED("SOCKET"); 
    else 
        SYSCALL_NO_VERIFIED("SOCKET"); 

    execution_public_variant(ths, public,  &result);  

    int index = get_free_fd(ths);
    if ( index < 0 )
      irreversible_error("FD space full"); 
    ths->fd_maps[index].fd         = (int)result.result; 
    ths->fd_maps[index].type       = SOCKET_FD; 
    ths->fd_maps[index].visibility = PUBLIC; 

    DPRINT(DEBUG_INFO, "Added file descriptor %d to the public list\n", ths->fd_maps[index].fd );

    printf("[ public  ] socket(%ld, %lx, %lx) = %ld\n", public->regs.arg0,  public->regs.arg1, private->regs.arg2, result.result); 
    printf("[ private ] socket(%ld, %lx, %lx) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); 

    return; 
}

void server_setsockopt( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 
    char * private_buffer= NULL, *public_buffer = NULL; 
    size_t size_buf = 0; 
    ssize_t transfered= -1; 
    bool buffer_match =false; 

    assert(public->syscall_num  == __NR_setsockopt && 
           private->syscall_num == __NR_setsockopt ); 
    assert(public->regs.arg4 ==  private->regs.arg4);  

    size_buf = public->regs.arg4; 
    private_buffer = calloc(size_buf, 1); 
    public_buffer = calloc(size_buf, 1); 

    transfered = get_extra_arguments(ths->fds[PUBLIC_UNTRUSTED],public_buffer,
                  ths->fds[PRIVATE_UNTRUSTED], private_buffer , size_buf);
  
    if ( transfered < 0 )
      die("Error extra argument SETSOCKOPR");

    assert( (size_t)transfered == size_buf); 
    buffer_match = !memcmp(public_buffer, private_buffer, size_buf);

    if ( (public->regs.arg0 == private->regs.arg0) && buffer_match && 
         (public->regs.arg1 == private->regs.arg1) &&
         (public->regs.arg2 == private->regs.arg2) && 
         (public->regs.arg4 == private->regs.arg4) )
        SYSCALL_VERIFIED("SETSOCKOPT"); 
    else 
        SYSCALL_NO_VERIFIED("SETSOCKOPT"); 

    assert(is_fd_public(ths, (int)public->regs.arg0));
    execution_public_variant(ths, public,  &result);  

    printf("[ public  ] setsockopt(%ld, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = %ld\n", public->regs.arg0,  public->regs.arg1, private->regs.arg2,
                                                                              public->regs.arg3,  public->regs.arg4, result.result); 
    printf("[ private ] setsockopt(%ld, 0x%lx, 0x%lx, 0x%lx, 0x%lx) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2,  
                                                                              private->regs.arg3, private->regs.arg4, result.result); 
    return; 
}

void server_bind( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 
    char * private_buffer= NULL, *public_buffer = NULL; 
    size_t size_buf = 0; 
    ssize_t transfered= -1; 
    bool buffer_match =false; 

    assert(public->syscall_num  == __NR_bind && 
           private->syscall_num == __NR_bind ); 
    assert(public->regs.arg2 ==  private->regs.arg2); 

    size_buf = public->regs.arg2; 
    private_buffer = calloc(size_buf, 1); 
    public_buffer = calloc(size_buf, 1); 

    transfered = get_extra_arguments(ths->fds[PUBLIC_UNTRUSTED],public_buffer,
                  ths->fds[PRIVATE_UNTRUSTED], private_buffer , size_buf);
 
    if ( transfered < 0)
      die("Error extra argument BIND"); 
    assert((size_t)transfered == size_buf); 
    buffer_match = !memcmp(public_buffer, private_buffer, size_buf);

    if ( (public->regs.arg0 == private->regs.arg0) && buffer_match && 
         (public->regs.arg2 == private->regs.arg2) )
      SYSCALL_VERIFIED("BIND"); 
    else 
      SYSCALL_NO_VERIFIED("BIND"); 

    assert(is_fd_public(ths, public->regs.arg0)); 
    execution_public_variant(ths, public,  &result);  

    printf("[ public  ] bind(%ld, 0x%lx, 0x%lx) = %ld\n", public->regs.arg0,  public->regs.arg1, private->regs.arg2, result.result); 
    printf("[ private ] bind(%ld, 0x%lx, 0x%lx) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); 

    return; 
}

void server_listen( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 

    assert(public->syscall_num  == __NR_listen && 
           private->syscall_num == __NR_listen ); 

    if ( (public->regs.arg0 == private->regs.arg0) && 
         (public->regs.arg1 == private->regs.arg1) )
        SYSCALL_VERIFIED("LISTEN"); 
    else 
        SYSCALL_NO_VERIFIED("LISTEN"); 

    assert(is_fd_public(ths, public->regs.arg0)); 
    execution_public_variant(ths, public,  &result);  

    printf("[ public  ] listen(%ld, 0x%lx) = %ld\n", public->regs.arg0,  public->regs.arg1, result.result); 
    printf("[ private ] listen(%ld, 0x%lx) = %ld\n", private->regs.arg0, private->regs.arg1, result.result); 

    return; 
}
/********************************************************************/

void server_epoll_create( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 

    assert(public->syscall_num == private->syscall_num); 

    if (public->regs.arg0 == private->regs.arg0) 
        SYSCALL_VERIFIED("EPOLL_CREATE"); 
    else 
        SYSCALL_NO_VERIFIED("EPOLL_CREATE"); 

    // this is not cmpletely true, a better solution should be to execute in both variant
    execution_public_variant(ths, public, &result);  

    int index = get_free_fd(ths); 
    if (index < 0)
      irreversible_error("FD space full"); 
    
    ths->fd_maps[index].fd         = (int)result.result; 
    ths->fd_maps[index].type       = POLL_FD; 
    ths->fd_maps[index].visibility = PUBLIC; 

    DPRINT(DEBUG_INFO, "Insert fd %d at the indext %d\n", ths->fd_maps[index].fd,index); 
    
    printf("[ public  ] epoll_create(0x%lx) = %ld\n", public->regs.arg0, result.result); 
    printf("[ private ] epoll_create(0x%lx) = %ld\n", private->regs.arg0, result.result); 

    return; 
}

void server_epoll_ctl( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 
    struct epoll_event private_str, public_str; 
    bool buffer_match; 

    assert(public->syscall_num == private->syscall_num); 

    get_extra_arguments(ths->fds[PUBLIC_UNTRUSTED], (char *)&public_str, ths->fds[PRIVATE_UNTRUSTED],
                        (char *)&private_str, sizeof(struct epoll_event)); 
    
    buffer_match = memcmp((char *)&public_str, (char *)&private_str, sizeof(struct epoll_event))? false : true; 

    if ( (public->regs.arg0 == private->regs.arg0 ) &&  buffer_match &&
         (public->regs.arg1 == private->regs.arg1 ) &&  
         (public->regs.arg2 == private->regs.arg2 ) )
        SYSCALL_VERIFIED("EPOLL_CTL"); 
    else 
        SYSCALL_NO_VERIFIED("EPOLL_CTL"); 

    assert(is_fd_public(ths, public->regs.arg0) && get_fd_type(ths, public->regs.arg0, PUBLIC) == POLL_FD); 
    execution_public_variant(ths, public, &result);  
    
    printf("[ public  ] epoll_ctl(%ld, 0x%lx, %ld, 0x%lx) = %ld\n", public->regs.arg0, public->regs.arg1,
                                                    public->regs.arg2,  public->regs.arg3, result.result); 
    printf("[ private ] epoll_ctl(%ld, 0x%lx, %ld, 0x%lx) = %ld\n", private->regs.arg0, private->regs.arg1 ,
                                                    private->regs.arg2, private->regs.arg3, result.result); 
    return; 
}

void server_epoll_wait( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 
    struct epoll_event private_str, public_str; 
    bool buffer_match; 

    assert(public->syscall_num == private->syscall_num); 

    get_extra_arguments(ths->fds[PUBLIC_UNTRUSTED], (char *)&public_str, ths->fds[PRIVATE_UNTRUSTED],
                        (char *)&private_str, sizeof(struct epoll_event)); 
    
    buffer_match = memcmp((char *)&public_str, (char *)&private_str, sizeof(struct epoll_event))? false : true; 

    if ( (public->regs.arg0 == private->regs.arg0 ) && buffer_match &&  
         (public->regs.arg2 == private->regs.arg2 ) &&  
         (public->regs.arg3 == private->regs.arg3 ) )
        SYSCALL_VERIFIED("EPOLL_WAIT"); 
    else 
        SYSCALL_NO_VERIFIED("EPOLL_WAIT"); 

    assert(is_fd_public(ths, public->regs.arg0) && get_fd_type(ths, public->regs.arg0, PUBLIC) == POLL_FD); 

    execution_public_variant_with_extra(ths, public, &result, sizeof(struct epoll_event));  
    
    printf("[ public  ] epoll_wait(%ld, 0x%lx, %ld, %ld) = %ld\n", public->regs.arg0, public->regs.arg1,
                                                    public->regs.arg2,  public->regs.arg3, result.result); 
    printf("[ private ] epoll_wait(%ld, 0x%lx, %ld, %ld) = %ld\n", private->regs.arg0, private->regs.arg1 ,
                                                    private->regs.arg2, private->regs.arg3, result.result); 
    return; 
}
   
void server_accept( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 
    socklen_t public_len, private_len; 
    bool buffer_match; 
    ssize_t transfered = -1; 

    assert(public->syscall_num == private->syscall_num); 

    get_extra_arguments(ths->fds[PUBLIC_UNTRUSTED], (char *)&public_len, ths->fds[PRIVATE_UNTRUSTED],
                        (char *)&private_len, sizeof(socklen_t)); 
    
    buffer_match = (public_len == private_len ) ? true : false ; 
    
    if ( (public->regs.arg0 == private->regs.arg0 ) &&  buffer_match )
       SYSCALL_VERIFIED("ACCEPT"); 
    else 
       SYSCALL_NO_VERIFIED("ACCEPT"); 

    assert(is_fd_public(ths, public->regs.arg0) && get_fd_type(ths, public->regs.arg0, PUBLIC) == SOCKET_FD);
    
    if(forward_syscall_request(ths->fds[PUBLIC_TRUSTED], public) < 0)
            die("Failed send request to trusted thread");

   if (receive_syscall_result_async(ths->fds[PUBLIC_TRUSTED], &result) < 0) 
        die("Error receiving result from the truste thread"); 

    assert(result.extra); 
    // extra contains the size of the structures 
    char * buf = malloc(result.extra); 
    size_t size = (size_t)result.extra; 
    ssize_t r;

    if ((r=read(ths->fds[PUBLIC_TRUSTED], buf, size)) < 0) 
        die("Error accpet reading values"); 

    assert(r == size);

    result.cookie = private->cookie;
    if((transfered=send_result_with_extra(ths->fds[PRIVATE_UNTRUSTED], &result, buf, size)) < 0)
       die("Failed sending result (READ)");

   CHECK(transfered, size + SIZE_RESULT, result.extra);  
 
   result.cookie = public->cookie;
   result.extra  = 0;
   // send results to the untrusted thread private  
   if(forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], &result) < 0)
       die("Failed send request public trusted thread");
    
   /****************************************************************/
    // FD
    if (save_fd(ths, result.result, SOCKET_FD, PUBLIC) < 0 )  
        irreversible_error("FD space finished"); 
    
    printf("FD : %d %d\n", (int)result.result, is_fd_public(ths, result.result)); 
    assert(is_fd_public(ths, result.result));  
    
    printf("[ public  ] accept(%ld, 0x%lx, 0x%lx(%d)) = %ld\n", public->regs.arg0, public->regs.arg1,
                                                    public->regs.arg2,  public_len, result.result); 
    printf("[ private ] accept(%ld, 0x%lx, 0x%lx(%d)) = %ld\n", private->regs.arg0, private->regs.arg1 ,
                                                    private->regs.arg2, private_len, result.result); 
    return; 
}

void server_writev ( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 
    struct iovec * private_io, *public_io;
    size_t num_buffers=0;
    const size_t size_iovec = sizeof(struct iovec);
    bool buffer_match = false; 

    DPRINT(DEBUG_INFO, "WRITEV SYSTEM CALL\n"); 
    CLEAN_RES(&result); 

    assert( public->syscall_num == __NR_writev && private->syscall_num == __NR_writev); 
    assert (public->regs.arg2  == private->regs.arg2); 
    num_buffers = public->regs.arg2; 
  
    public_io =  calloc ( size_iovec, num_buffers);
    private_io = calloc ( size_iovec, num_buffers);

    get_extra_arguments(ths->fds[PUBLIC_UNTRUSTED],  (char*)public_io,
                        ths->fds[PRIVATE_UNTRUSTED], (char*)private_io, size_iovec * num_buffers); 

    DPRINT(DEBUG_INFO, "Number of buffers %lu\n", num_buffers); 


    for ( int i = 0; i < (int)num_buffers; i++) {

      assert(private_io[i].iov_len == public_io[i].iov_len);
    
      private_io[i].iov_base = malloc(private_io[i].iov_len);
      public_io[i].iov_base  = malloc(public_io[i].iov_len);

      if (!private_io[i].iov_base  ||  !public_io[i].iov_base)
          die("Warning allication buffer error");     
    
      DPRINT(DEBUG_INFO, "Public  allocate %lu at %p  index %d\n", public_io[i].iov_len,  public_io[i].iov_base, i);
      DPRINT(DEBUG_INFO, "Private allocate %lu at %p  index %d\n", private_io[i].iov_len, private_io[i].iov_base, i);

    }
  
    if (readv(ths->fds[PUBLIC_UNTRUSTED],  public_io,  num_buffers) < 0 ) 
        die("readv"); 
    
    if (readv(ths->fds[PRIVATE_UNTRUSTED],  private_io,  num_buffers) < 0 ) 
        die("readv"); 
   
    buffer_match = true; 
    for ( int i = 0; i < (int)num_buffers; i++) 
        buffer_match &= !memcmp(private_io[i].iov_base, public_io[i].iov_base, public_io[i].iov_len); 
      

    if ( public->regs.arg0 == private->regs.arg0 &&  buffer_match &&
         public->regs.arg2 == private->regs.arg2 ) 
        SYSCALL_VERIFIED("WRITEV"); 
    else 
        SYSCALL_NO_VERIFIED("WRITEV"); 

   if(IS_STD_FD(public->regs.arg0) && IS_STD_FD(private->regs.arg0)) {
         DPRINT(DEBUG_INFO, "WRITEV called with default file descriptor\n"); 
         server_default(ths, public, private);
         return;
   } 

   if (is_fd_private(ths, public->regs.arg0)){
      execution_private_variant(ths, private, &result);  
   } else {
      assert(is_fd_public(ths, public->regs.arg0) && !is_fd_private(ths, public->regs.arg0));
      execution_public_variant(ths, public, &result); 
   }

    printf("[ PUBLIC  ] writev(%ld, %lx, %ld) = %ld\n", public->regs.arg0,  public->regs.arg1, private->regs.arg2, result.result); 
    printf("[ PRIVATE ] writev(%ld, %lx, %ld) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); 

    for ( int i = 0; i < (int)num_buffers; i++){
      free(private_io[i].iov_base);
      free(public_io[i].iov_base);
    }

    free(private_io); 
    free(public_io); 
    return; 
}


/************** INSTALL SERVER HANDLER *****************************/ 
void initialize_server_handler() { 

   static struct server_policy { 
       int syscall_num; 
       void (*handler)(struct thread_group *  ,const struct syscall_header*,const struct  syscall_header *); 
   } default_policy [] = {
        /*server handler */
      { __NR_exit_group,     server_exit_group },
      { __NR_open,           server_open       },
      { __NR_openat,         server_openat     },
      { __NR_fstat,          server_fstat      },
      { __NR_stat,           server_stat       },
      { __NR_getdents,       server_getdents   },
      { __NR_mmap,           server_mmap       },
      { __NR_close,          server_close      },
      { __NR_write,          server_write      },
      { __NR_writev,         server_writev     },
      { __NR_read,           server_read       }, 
      { __NR_lseek,          server_lseek      }, 
      { __NR_ioctl,          server_ioctl      }, 
      { __NR_fcntl ,         server_fcntl      }, 
      { __NR_getpid,         server_getpid     }, 
      { __NR_getcwd,         server_getcwd     }, 
      { __NR_getuid,         server_getuid     }, 
      { __NR_socket,         server_socket     }, 
      { __NR_bind,           server_bind       }, 
      { __NR_listen,         server_listen     }, 
      { __NR_accept,         server_accept     }, 
      { __NR_setsockopt,     server_setsockopt }, 
      { __NR_epoll_create,   server_epoll_create}, 
      { __NR_epoll_ctl,      server_epoll_ctl   }, 
      { __NR_epoll_wait,     server_epoll_wait  }, 
   }; 

   syscall_table_server_ = (struct server_handler *)malloc( MAX_SYSTEM_CALL * (sizeof( struct server_handler))); 

  if (!syscall_table_server_) 
      die("Failed allocation memory for server handlers"); 

    /*default initiailization */
    for (struct server_handler * serv_handler=syscall_table_server_; 
            serv_handler < syscall_table_server_ + MAX_SYSTEM_CALL; 
            serv_handler++)
        serv_handler->handler = DEFAULT_SERVER_HANDLER; 

    /*install policy */
  for (const struct server_policy *policy = default_policy;
       policy-default_policy < (int)(sizeof(default_policy)/sizeof(struct server_policy));
       ++policy) 
           syscall_table_server_[policy->syscall_num].handler = policy->handler; 

  DPRINT(DEBUG_INFO, "System call handlers installed\n"); 

} 
/*******************************************************************/ 
