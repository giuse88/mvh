
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
int get_public_fd(const struct thread_group * ths, int private) {
    for (int i=0; i < MAX_FD; i++) 
        if (ths->fd_maps[i].private == private)
            return ths->fd_maps[i].public; 
    return -1; 
}
int get_private_fd(const struct thread_group *ths, int public) {
    for (int i=0; i < MAX_FD; i++) 
        if (ths->fd_maps[i].public == public)
            return ths->fd_maps[i].private; 
    return -1; 
}
int free_fd(struct thread_group * ths, int private, int public){
    for (int i=0; i < MAX_FD; i++)
        if ( ths->fd_maps[i].private == private &&
             ths->fd_maps[i].public == public)  {
            memset(&ths->fd_maps[i],0, sizeof( struct fd_pair));
            return SUCCESS; 
        }
    return -1; 
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

/*************************** HANDLERS ******************************/ 
void server_default ( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) { 
 
    struct syscall_result public_result, private_result; 
    bool pub_res=false; 
    bool priv_res=false; 
    int res =-1; 
    bool completed=false; 

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
   
    do { 

    res=poll(ths->pollfds,NFDS,SERVER_TIMEOUT); 

    if (res == 0)
            irreversible_error("Connection Time out"); 
    else if ( res < 0 )
            die("pool"); 

   if (ths->pollfds[PUBLIC_TRUSTED].revents) {
        pub_res=true; 
        receive_syscall_result(ths->fds[PUBLIC_TRUSTED], &public_result); 
        DPRINT(DEBUG_INFO, "Received result for %d from %d over %d\n", public_result.cookie, ths->public.trusted.tid, ths->fds[PUBLIC_TRUSTED]);
      }

    if (ths->pollfds[PRIVATE_TRUSTED].revents) {
        priv_res = true; 
        receive_syscall_result(ths->fds[PRIVATE_TRUSTED], &private_result);
        DPRINT(DEBUG_INFO, "Received result for %d from %d over %d\n", private_result.cookie, ths->private.trusted.tid,ths->fds[PRIVATE_TRUSTED]);
    }

 
    /*//TODO I should also verify the cookie */ 
    
    if( pub_res && priv_res) {
        syscall_info(public, &public->regs,  &public_result, PUBLIC); 
        syscall_info(private,&private->regs, &private_result, PRIVATE); 
        
        if(forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], &public_result) < 0)
            die("Failed send request public trusted thread");
        if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &private_result) < 0)
            die("Failed send request public trusted thread");
       
        completed = true; 
        pub_res = false;
        priv_res = false; 
        CLEAN_RES(&public_result); 
        CLEAN_RES(&private_result); 
    }
   
    } while(!completed); 

    return; 
}

void server_open ( struct thread_group* ths, const struct syscall_header * public , const struct syscall_header * private) {

   char * public_path = NULL,* private_path = NULL; 
   int length =-1; 
   struct syscall_result private_result, public_result; 

   DPRINT(DEBUG_INFO, "Open SYSTEM CALL\n"); 

   CLEAN_RES(&public_result); 
   CLEAN_RES(&private_result); 

   assert( public->syscall_num == __NR_open && private->syscall_num == __NR_open); 
   assert( public->extra == private->extra); 
   
   length = public->extra; 
   public_path = malloc(length); 
   private_path = malloc(length); 

   if (get_extra_argument(ths->fds[PUBLIC_UNTRUSTED], ths->fds[PRIVATE_UNTRUSTED],  public_path, private_path, length) < 0)
        die("Failed get_path()"); 

   if (!strncmp(private_path, public_path, length) &&
        public->regs.arg1 == private->regs.arg1)
       SYSCALL_VERIFIED("OPEN"); 
   else 
       SYSCALL_NO_VERIFIED("OPEN"); 
  
   // sends the request to the private application 
  if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
            die("failed send request public trusted thread");
  
  // gets system call results  
  if(receive_syscall_result_async(ths->fds[PRIVATE_TRUSTED], &private_result) < 0)  
            die("failed receive system call result"); 

  // send results to the untrusted thread private 
  if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &private_result) < 0)
        die("Failed send request public trusted thread");

  srand(time(NULL)); 

  public_result.cookie = public->cookie; 
  public_result.result = rand() % 1000; 
  public_result.extra  = 0; 
 
  int index_fd = get_free_fd(ths); 
  ths->fd_maps[index_fd].type    = FILE_FD; 
  ths->fd_maps[index_fd].public  = public_result.result; 
  ths->fd_maps[index_fd].private = private_result.result;

  DPRINT(DEBUG_INFO, "Added fd to the to fd table %d = [%d:%d]\n",index_fd, 
              ths->fd_maps[index_fd].private, ths->fd_maps[index_fd].public); 

  // send fake result to the untrusted public 
  if(forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], &public_result) < 0)
           die("Failed send request public trusted thread");

  printf("[ PUBLIC  ] open(%s, %lx) = %ld\n", public_path,  public->regs.arg1 , public_result.result ); 
  printf("[ PRIVATE ] open(%s, %lx) = %ld\n", private_path, private->regs.arg1, private_result.result); 

  free(public_path);
  free(private_path); 

  return; 
} 

void server_fstat ( struct thread_group* ths, const struct syscall_header * public , const struct syscall_header * private){

    struct syscall_result result; 
    struct stat res_fstat;

    DPRINT(DEBUG_INFO, "Start fstat handler\n"); 

    // sanity checks 
    assert( public->syscall_num == __NR_fstat  && private->syscall_num == __NR_fstat); 
    

    if ( public->regs.arg0 == private->regs.arg0 && 
         IS_STD_FD(public->regs.arg0) && IS_STD_FD(private->regs.arg0)) {
         DPRINT(DEBUG_INFO, "Fstat invoked with default file descriptor\n"); 
         server_default(ths, public, private);
         return;
    } 
    
    if ((get_private_fd(ths, public->regs.arg0) == (int)private->regs.arg0) && 
        (get_public_fd(ths, private->regs.arg0) == (int)public->regs.arg0))
        SYSCALL_VERIFIED("FSTAT"); 
    else 
        SYSCALL_NO_VERIFIED("FSTAT"); 


    /* ACTIONS  
     * Send request to the private version 
     * get the result and the fstat structure from the private trusted thread 
     * send back a normal result to the private version 
     * send back the result and the stat structure to the pucliv untrusted
     * No handler are need for the trusted public thread 
     */ 

    CLEAN_RES(&result); 
    memset(&res_fstat, 0, sizeof(res_fstat)); 

    // sends the request to the private application 
    if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
            die("failed send request public trusted thread");
  
   // gets system call result and the fstat struct from the memory space of the private 
   // truste thread 
    struct iovec io[2];
    struct msghdr msg; 
    int transfered=-1; 

    memset(&msg, 0, sizeof(msg));
    memset(io, 0, sizeof(io)); 
    
    // result header 
    io[0].iov_len=SIZE_RESULT; 
    io[0].iov_base=&result;
    // result fstat
    io[1].iov_len = sizeof(struct stat); 
    io[1].iov_base = &res_fstat; 
    // IOV struct 
    msg.msg_iov=io;
    msg.msg_iovlen=2; 
 
    ASYNC_CALL(recvmsg(ths->fds[PRIVATE_TRUSTED],&msg, 0), transfered); 
    if ( transfered < 0) 
        die("Recvmsg (Fstat handler)"); 
   
    assert(transfered == SIZE_RESULT +sizeof(struct stat)); 
   
   // send results to the untrusted thread private  
    if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &result) < 0)
        die("Failed send request public trusted thread");

    result.cookie = public->cookie; 
    // send result header along with the fsstat to the public trusted process 
    transfered = sendmsg(ths->fds[PUBLIC_UNTRUSTED], &msg, 0);
    assert(transfered == SIZE_RESULT +sizeof(struct stat)); 

    printf("[ PUBLIC  ] fstat(%ld, %lx) = %ld\n", public->regs.arg0,  public->regs.arg1, result.result); 
    printf("[ PRIVATE ] fstat(%ld, %lx) = %ld\n", private->regs.arg0, private->regs.arg1, result.result); 

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
   assert( get_private_fd(ths,public->regs.arg4) == (int)private->regs.arg4); 
   assert( get_public_fd(ths,private->regs.arg4) == (int)public->regs.arg4); 
   
   if ((public->regs.arg1 == private->regs.arg1) &&  
        (public->regs.arg2 == private->regs.arg2) &&  
        (public->regs.arg3 == private->regs.arg3) &&
        (public->regs.arg5 == private->regs.arg5)) 
    SYSCALL_VERIFIED("MMAP"); 
   else 
    SYSCALL_NO_VERIFIED("MMAP");
    
   map_size = public->regs.arg1; 
   flags= public->regs.arg3; 
   // MAP_ANONYMOUS 0x20 00100000
   // MAP_ANO == MAP_ANONIMOUS 
   if (flags & MAP_ANONYMOUS) { 
      DPRINT(DEBUG_INFO, "MMAP invoked with MAP_ANONYMOUS. Default behaviour\n");         
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
  int size=-1;
  if((size=receive_result_with_extra(ths->fds[PRIVATE_TRUSTED], &private_result, buf, map_size)) < 0) 
        die("Failed receiving result with extra\n"); 

  DPRINT(DEBUG_INFO, "File received correctly size %d\n", size); 
  
   // unfortunately I cannot send the file along with the result because
  // I don't know the mapping address and I cannot neither call malloc
  // to allocate a temporary storage area. 
  // send the result to the untrusted   
  if(forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], &public_result) < 0)
      die("Failed forwarding result with extra  to the public thread\n"); 
  // send file
  send_extra(ths->fds[PUBLIC_UNTRUSTED], buf, map_size); 
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

   DPRINT(DEBUG_INFO, "CLOSE SYSTEM CALL\n"); 
   
   CLEAN_RES(&result); 

   // sanity checks 
   assert( public->syscall_num == __NR_close && private->syscall_num == __NR_close);

    if ( public->regs.arg0 == private->regs.arg0 && 
         IS_STD_FD(public->regs.arg0) && IS_STD_FD(private->regs.arg0)) {
          SYSCALL_VERIFIED("CLOSE"); 
          DPRINT(DEBUG_INFO, "CLOSE invoked with default file descriptor\n"); 
          server_default(ths, public, private);
          return;
    } 
  
  if ( (get_private_fd(ths,public->regs.arg0) == (int)private->regs.arg0) &&  
        (get_public_fd(ths,private->regs.arg0) == (int)public->regs.arg0))
      SYSCALL_VERIFIED("CLOSE"); 
  else 
      SYSCALL_NO_VERIFIED("CLOSE"); 
  
  if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
           die("failed send request public trusted thread");

  if(receive_syscall_result_async(ths->fds[PRIVATE_TRUSTED], &result) < 0)  
            die("failed receive system call result");

  if (free_fd(ths, (int)private->regs.arg0, (int)public->regs.arg0) < 0) 
      die("Error, tried to free an incorrect fd");  
  else 
      DPRINT(DEBUG_INFO, "Remove fd pair [%ld:%ld]\n", private->regs.arg0, public->regs.arg0); 

  if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &result) < 0)
      die("Failed forwarding result private thread\n"); 
  
  result.cookie = public->cookie;  
 
  if(forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], &result) < 0)
      die("Failed forwarding result with extra  to the public thread\n"); 

  printf("[ PUBLIC  ] close(%ld) = %ld\n", public->regs.arg0, result.result); 
  printf("[ PRIVATE ] close(%ld) = %ld\n", private->regs.arg0,result.result); 


  
  return; 
}

void server_openat ( struct thread_group* ths, const struct syscall_header * public , const struct syscall_header * private) {

    char * public_path = NULL,* private_path = NULL; 
    int length =-1; 
    struct syscall_result private_result, public_result; 

    DPRINT(DEBUG_INFO, "Openat SYSTEM CALL\n"); 

 
   CLEAN_RES(&public_result); 
   CLEAN_RES(&private_result); 

   assert( public->syscall_num == __NR_openat && private->syscall_num == __NR_openat); 
   assert( public->extra == private->extra); 
   
   length = public->extra; 
   public_path = malloc(length); 
   private_path = malloc(length); 

   if (get_extra_argument(ths->fds[PUBLIC_UNTRUSTED], ths->fds[PRIVATE_UNTRUSTED],  public_path, private_path, length) < 0)
        die("Failed get_path()"); 

   if ( !strncmp(private_path, public_path, length) &&
       (public->regs.arg2 == private->regs.arg2) && 
       (public->regs.arg0 == private->regs.arg0))
       SYSCALL_VERIFIED("OPENAT");
   else 
       SYSCALL_NO_VERIFIED("OPENAT");

  
   // sends the request to the private application 
  if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
            die("failed send request public trusted thread");
  
  // gets system call results  
  if(receive_syscall_result_async(ths->fds[PRIVATE_TRUSTED], &private_result) < 0)  
            die("failed receive system call result"); 

  // send results to the untrusted thread private 
  if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &private_result) < 0)
        die("Failed send request public trusted thread");

  srand(time(NULL)); 

  public_result.cookie = public->cookie; 
  public_result.result = rand() % 1000; 
  public_result.extra  = 0; 

  int index = get_free_fd(ths); 
  ths->fd_maps[index].type = FILE_FD; 
  ths->fd_maps[index].public = public_result.result; 
  ths->fd_maps[index].private = private_result.result;

  DPRINT(DEBUG_INFO, "Added fd to the to fd table %d = [%d:%d]\n",index, 
              ths->fd_maps[index].private, ths->fd_maps[index].public); 

  // send fake result to the untrusted public 
  if(forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], &public_result) < 0)
           die("Failed send request public trusted thread");

  printf("[ PUBLIC  ] openat(%lx, %s, %lx) = %ld\n", public->regs.arg0, public_path,  public->regs.arg2, public_result.result); 
  printf("[ PRIVATE ] openat(%lx, %s, %lx) = %ld\n", private->regs.arg0, private_path, private->regs.arg2, private_result.result); 

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
    char * buf = NULL; 
    size_t size=0; 
    ssize_t transfered=0;  

    DPRINT(DEBUG_INFO, "Start fstat handler\n"); 

    // sanity checks 
    assert( public->syscall_num == __NR_read  && private->syscall_num == __NR_read); 
    
    // reading from the standard input
    if ( public->regs.arg0 == private->regs.arg0 && 
         IS_STD_FD(public->regs.arg0) && IS_STD_FD(private->regs.arg0)) {
         DPRINT(DEBUG_INFO, "READ invoked with default file descriptor\n"); 
         server_default(ths, public, private);
         return;
    } 
    
    if ((get_private_fd(ths,public->regs.arg0) == (int)private->regs.arg0) && 
        (get_public_fd(ths,private->regs.arg0) == (int)public->regs.arg0) && 
        public->regs.arg2 == private->regs.arg2)
        SYSCALL_VERIFIED("READ"); 
    else 
        SYSCALL_NO_VERIFIED("READ"); 

    CLEAN_RES(&result);
    size = public->regs.arg2; 
    buf = malloc(size);
    
    // sends the request to the private application 
    if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
            die("failed send request public trusted thread");
    //receive result with extra 
    if ( (transfered=receive_result_with_extra(ths->fds[PRIVATE_TRUSTED], &result, buf, size)) < 0) 
        die("Error receiving result(READ)"); 
    assert((size_t)transfered == (SIZE_RESULT + size) ); 
   
   // send results to the untrusted thread private  
    if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &result) < 0)
        die("Failed send request public trusted thread");
    result.cookie = public->cookie; 
    if((transfered=send_result_with_extra(ths->fds[PUBLIC_UNTRUSTED], &result, buf, size)) < 0)
        die("Failed sending result (READ)"); 
   
    assert((size_t)transfered == (SIZE_RESULT + size) ); 
    free(buf); 

    printf("[ PUBLIC  ] read(%ld, 0x%lx, 0x%lx) = %ld\n", public->regs.arg0,  public->regs.arg1,  public->regs.arg2,  result.result); 
    printf("[ PRIVATE ] read(%ld, 0x%lx, 0x%lx) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); 

    return; 
}

void server_getdents ( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private){

    struct syscall_result result; 
    char * buf = NULL; 
    size_t size_buf = 0; 
    ssize_t  transfered =-1; 
    
    DPRINT(DEBUG_INFO, "Start GETDENTS handler\n"); 

    // sanity checks 
    assert( public->syscall_num == __NR_getdents  && private->syscall_num == __NR_getdents); 
    
    if   ( (public->regs.arg2 == private->regs.arg2) && 
           (get_private_fd(ths, public->regs.arg0) == (int)private->regs.arg0) && 
           (get_public_fd(ths, private->regs.arg0) == (int)public->regs.arg0)) 
       SYSCALL_VERIFIED("GETDENTS");
    else 
       SYSCALL_NO_VERIFIED("GETDENTS"); 

    CLEAN_RES(&result); 
   
    // send request to the trusted private
    if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
            die("failed send request public trusted thread");
    
    size_buf = public->regs.arg2; 
    buf = malloc(size_buf);  
    if (!buf) 
        die("Failed malloc (GETDENTS)"); 
    else 
        DPRINT(DEBUG_INFO, "Reserved %lu for temporary storage\n", size_buf); 

    // receive result along with the buffer
    transfered = receive_result_with_extra(ths->fds[PRIVATE_TRUSTED], &result, buf, size_buf);  
    if ( transfered < 0) 
        die("Recvmsg (GETDENTS)"); 
 
    // sanity check 
    assert(transfered == (ssize_t)(SIZE_RESULT + size_buf));  
   
       // send results to the untrusted thread private  
    if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &result) < 0)
        die("Failed send request public trusted thread");

    result.cookie = public->cookie; 
    
    transfered = send_result_with_extra(ths->fds[PUBLIC_UNTRUSTED], &result, buf, size_buf);  
    if ( transfered < 0) 
        die("Send result with extra (GETDENTS)"); 
  
    assert(transfered == (ssize_t)(SIZE_RESULT + size_buf));  
    free(buf); 

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
   // assert( public->regs.arg2 == private->regs.arg2); 

    size = public->regs.arg2; 
    public_buf   = malloc(size); 
    private_buf  = malloc(size); 
    get_extra_arguments(ths->fds[PUBLIC_UNTRUSTED],public_buf, ths->fds[PRIVATE_UNTRUSTED], private_buf, size); 


    buffer_match = memcmp(public_buf, private_buf, size)? false : true; 

    if ( ( public->regs.arg0 == private->regs.arg0) && 
         IS_STD_FD(public->regs.arg0) && IS_STD_FD(private->regs.arg0)) {
            SYSCALL_VERIFIED("WRITE");  
            DPRINT(DEBUG_INFO, "WRITE invoked with default file descriptor\n"); 
            server_default(ths, public, private);
            return;
    } 
 
    if ((get_private_fd(ths, public->regs.arg0) == (int)private->regs.arg0) && 
        (get_public_fd(ths, private->regs.arg0) == (int)public->regs.arg0)  &&
         ( public->regs.arg2 == private->regs.arg2) && buffer_match )
         SYSCALL_VERIFIED("WRITE");  
    else 
        SYSCALL_NO_VERIFIED("WRITE"); 

    // sends the request to the private application 
    if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
            die("failed send request public trusted thread");

    // gets system call results  
    if(receive_syscall_result_async(ths->fds[PRIVATE_TRUSTED], &result) < 0)  
            die("failed receive system call result"); 

       // send results to the untrusted thread private  
    if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &result) < 0)
        die("Failed send request private untrusted thread");

    result.cookie = public->cookie; 
    
    if(forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], &result) < 0)
        die("Failed send request public untrusted thread");

    printf("[ PUBLIC  ] write(%ld, %lx, %ld) = %ld\n", public->regs.arg0,  public->regs.arg1, private->regs.arg2, result.result); 
    printf("[ PRIVATE ] write(%ld, %lx, %ld) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); 

    return; 
}

bool verify_ioctl( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private, char * public_buf, char * private_buf) {
    
    bool fd=false, command = false, buffer=false;

    if ( public->syscall_num != private->syscall_num)
         return false; 
    // verify FIRST ARGUMENT FD 
    if ( public->regs.arg0 == private->regs.arg0 && 
         IS_STD_FD(public->regs.arg0) && IS_STD_FD(private->regs.arg0))
            fd=true;    
    else if ((get_private_fd(ths, public->regs.arg0) == (int)private->regs.arg0) && 
             (get_public_fd(ths, private->regs.arg0) == (int)public->regs.arg0))
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

void server_ioctl ( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result;
    ssize_t transfered = -1;
    bool check=true; 

    DPRINT(DEBUG_INFO, "Start IOCTL handler\n"); 
    assert( public->syscall_num == __NR_ioctl  && private->syscall_num == __NR_ioctl); 
    
    // GET INPUT ARGUMENT 
    // LIGHTHTTP uses the IOCTL with output variables 
    //get_extra_arguments()
   
    check=verify_ioctl(ths, public, private, NULL, NULL); 

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
    
    // sends the request to the private application 
    if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
            die("failed send request public trusted thread");
  
    size_t size_buf = get_size_from_cmd(public->regs.arg1);
    char *buf = malloc(size_buf); 
    
    transfered = receive_result_with_extra(ths->fds[PRIVATE_TRUSTED], &result, buf, size_buf);  
    if ( transfered < 0) 
        die("Receive result with extra (IOCTL)"); 

    assert(transfered == (ssize_t)(SIZE_RESULT + size_buf) || (transfered == (SIZE_RESULT) && (int)result.result < 0)); 
    
    result.cookie = public->cookie; 
    transfered = send_result_with_extra(ths->fds[PUBLIC_UNTRUSTED], &result, buf, size_buf);  
    if ( transfered < 0) 
        die("Send result with extra (IOCTL)"); 
    
    assert(transfered == (ssize_t)(SIZE_RESULT + size_buf) || (transfered == (SIZE_RESULT) && (int)result.result < 0)); 

    result.cookie = private->cookie;
    // send results to the untrusted thread private  
    if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], &result) < 0)
        die("Failed send request public trusted thread");
    free(buf); 

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


    private_result.result = ths->private.trusted.pid; 
    private_result.cookie = private->cookie; 
    private_result.extra = 0; 
   
    public_result.result = ths->public.trusted.pid; 
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

void execution_private_variant(struct thread_group * ths, const struct syscall_header * public, const struct syscall_header * private, 
                                     struct syscall_result * result){

    CLEAN_RES(result);

    // sends the request to the private application 
    if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
            die("failed send request public trusted thread");

    //receive result with extra 
    if ( (receive_syscall_result_async(ths->fds[PRIVATE_TRUSTED], result)) < 0) 
        die("Error receiving result(READ)"); 
   
   // send results to the untrusted thread private  
    if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], result) < 0)
        die("Failed send request public trusted thread");

    result->cookie = public->cookie;
    // send results to the untrusted thread private  
    if(forward_syscall_result(ths->fds[PUBLIC_UNTRUSTED], result) < 0)
        die("Failed send request public trusted thread");
  
    return; 
}

void execution_private_variant_extra(struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private, 
    struct syscall_result * result,  size_t size){

    ssize_t transfered =-1; 
    char * buf = malloc(size);
    
    CLEAN_RES(result);

    // sends the request to the private application 
    if(forward_syscall_request(ths->fds[PRIVATE_TRUSTED], private) < 0)
            die("failed send request public trusted thread");

    //receive result with extra 
    if ( (transfered=receive_result_with_extra(ths->fds[PRIVATE_TRUSTED], result, buf, size)) < 0) 
        die("Error receiving result(READ)"); 
   
   CHECK(transfered, size + SIZE_RESULT, result->result); 
   // send results to the untrusted thread private  
    if(forward_syscall_result(ths->fds[PRIVATE_UNTRUSTED], result) < 0)
        die("Failed send request public trusted thread");

    result->cookie = public->cookie;
    if((transfered=send_result_with_extra(ths->fds[PUBLIC_UNTRUSTED], result, buf, size)) < 0)
        die("Failed sending result (READ)"); 
   
    CHECK(transfered, size + SIZE_RESULT, result->result); 
    free(buf); 
    return; 
}

void server_getcwd( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 

    if ( public->regs.arg1 == private->regs.arg1)
        SYSCALL_VERIFIED("GETCWD"); 
    else 
        SYSCALL_NO_VERIFIED("GETCWD"); 

    execution_private_variant_extra(ths, public, private, &result, public->regs.arg1);  

    printf("[ PUBLIC  ] getcwd(%lx, %ld) = %ld\n", public->regs.arg0,  public->regs.arg1,  result.result); 
    printf("[ PRIVATE ] getcwd(%lx, %ld) = %ld\n", private->regs.arg0, private->regs.arg1, result.result); 

    return; 
}

void server_getuid( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {

    struct syscall_result result; 

    if ( public->syscall_num == private->syscall_num)
        SYSCALL_VERIFIED("GETUID"); 
    else 
        SYSCALL_NO_VERIFIED("GETUID"); 

    execution_private_variant(ths, public, private, &result);  

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

    execution_private_variant_extra(ths, public, private, &result, sizeof( struct stat));  

    printf("[ PUBLIC  ] stat(%s, %lx) = %ld\n", public_buf,  public->regs.arg0,  result.result); 
    printf("[ PRIVATE ] stat(%s, %lx) = %ld\n", private_buf, private->regs.arg0, result.result); 

    free(public_buf); 
    free(private_buf);

    return; 
}



/*void server_stat( struct thread_group * ths, const struct syscall_header * public , const struct syscall_header * private) {*/

    /*printf("[ PUBLIC  ] write(%ld, %lx, %ld) = %ld\n", public->regs.arg0,  public->regs.arg1, private->regs.arg2, result.result); */
    /*printf("[ PRIVATE ] write(%ld, %lx, %ld) = %ld\n", private->regs.arg0, private->regs.arg1, private->regs.arg2, result.result); */

    /*return; */
/*}*/

/********************************************************************/

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
      { __NR_read,           server_read       }, 
      { __NR_ioctl,          server_ioctl      }, 
      { __NR_getpid,         server_getpid     }, 
      { __NR_getcwd,         server_getcwd     }, 
      { __NR_getuid,         server_getuid     }, 
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
