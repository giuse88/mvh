#include "trusted_thread.h" 
#include <pthread.h> 
#include <unistd.h> 
#include "common.h"
#include <asm/unistd.h>
#include "sandbox.h"
#include "syscall_table.h"
#include <sys/mman.h> 
#include <sys/syscall.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <semaphore.h> 
#include <asm/prctl.h>
#include <sys/prctl.h>

#include <stdlib.h> 
#include "tls.h" 
#include "handler.h"

extern char * syscall_names[];

#include "linux_syscall_support.h" 

#define   _GNU_SOURCE  1

#define STACK_SIZE 0x8000

// Semaphore to syncronize two thread
static sem_t binary_semaphore; 

asm(
    ".pushsection .text, \"ax\", @progbits\n"
    ".internal do_syscall\n"
    ".global do_syscall\n"
    "do_syscall:\n"
#if defined(__x86_64__)
    "push %rdi\n"
    "push %rsi\n"
    "push %rdx\n"
    "push %r10\n"
    "push %r8\n"
    "push %r9\n"
    // Set up syscall arguments
    "mov 0x00(%rdi), %rax\n"
    // Skip 0x08 (%rdi): this comes last
    "mov 0x10(%rdi), %rsi\n"
    "mov 0x18(%rdi), %rdx\n"
    "mov 0x20(%rdi), %r10\n"
    "mov 0x28(%rdi), %r8\n"
    "mov 0x30(%rdi), %r9\n"
    "mov 0x08(%rdi), %rdi\n"
    "syscall\n"
    "pop %r9\n"
    "pop %r8\n"
    "pop %r10\n"
    "pop %rdx\n"
    "pop %rsi\n"
    "pop %rdi\n"
    "ret\n"
#elif defined(__i386__)
    "push %ebx\n"
    "push %ecx\n"
    "push %edx\n"
    "push %esi\n"
    "push %edi\n"
    "push %ebp\n"
    "mov 4+24(%esp), %ecx\n"
    // Set up syscall arguments
    "mov 0x00(%ecx), %eax\n"
    "mov 0x04(%ecx), %ebx\n"
    // Skip 0x08 (%ecx): this comes last
    "mov 0x0c(%ecx), %edx\n"
    "mov 0x10(%ecx), %esi\n"
    "mov 0x14(%ecx), %edi\n"
    "mov 0x18(%ecx), %ebp\n"
    "mov 0x08(%ecx), %ecx\n"
    "int $0x80\n"
    "pop %ebp\n"
    "pop %edi\n"
    "pop %esi\n"
    "pop %edx\n"
    "pop %ecx\n"
    "pop %ebx\n"
    "ret\n"
#else
#error Unsupported target platform
#endif
    ".popsection\n"
    );

    
char * allocate_stack(size_t);  
int    connect_remote_process(struct connection_info * , thread_type , int );
void   print_thread_info(const struct thread_info * info);
/*void   print_syscall_info(const syscall_request * req); */


/* CLONE 
 * static void return_from_clone_syscall(void *stack) {*/

 /*struct ucontext * uc =  (struct ucontext * ) stack; */
 /*DPRINT(DEBUG_INFO, "Clone handler, installed new stack frame at %p, RIP = 0x%lx\n", stack, (long) uc->uc_mcontext.gregs[REG_RIP]); */
 /*asm volatile ( "mov %0, %%rsp\n"*/
                /*"mov $15, %%rax\n"*/
                /*"syscall\n"*/
                /*: */
                /*: "m"(stack) */
                /*: "memory"*/
              /*); */
/*}*/

/*static int handle_new_thread( void * stack) {*/
 /*DPRINT(DEBUG_INFO, "Handle new thread\n"); */
 /*create_trusted_thread(); */
 /*DPRINT(DEBUG_INFO, "Stack pointer %p \n", stack); */
 /*return_from_clone_syscall(stack);*/
 /*return 0; */
/*}*/

int  trusted_thread(void * arg)
{

  struct ThreadArgs *args = (struct ThreadArgs *) arg;
  pid_t untrusted_tid=  args->untrusted_thread_tid;
  
  struct thread_local_info local_info; 
  
  DPRINT(DEBUG_INFO, "Trusted thread %ld monitoring the untrusted thread %d\n", 
         syscall(SYS_gettid), args->untrusted_thread_tid); 
    
    // set local info 
    // This is similar to the tls of the untrusted thread
    // but is installed in the stack of this function rather than in the heap 
    // this ensures that each thread has is own copy and we don t 
    // need to use the gs register. 
  
  memset(&local_info, 0, sizeof(struct thread_local_info)); 
  local_info.my_tid = syscall(SYS_gettid); 
  local_info.monitored_thread_id = untrusted_tid;  
  local_info.fd_remote_process=
        connect_remote_process(&sandbox.connection, TRUSTED_THREAD, untrusted_tid); 
  
  if ( local_info.fd_remote_process <= 2)
    die("Failure to connect to the server"); 
  
  sem_post(&binary_semaphore); 
 
  DPRINT(DEBUG_INFO, "%s thread %d connected to the remote process over the socket %d\n", 
            local_info.monitored_thread_id ? "Trusted" : "Untrusted", 
            local_info.my_tid, local_info.fd_remote_process);

  while (ALWAYS) 
  {
    struct syscall_header request; 
    struct syscall_registers regs; 
    int nread=0; 
    int syscallNum=-1; 
    struct msghdr msg; 
    struct iovec io[1];

    memset(&request, 0, sizeof(request));
    memset(&regs, 0, sizeof(regs));
    memset(&msg, 0, sizeof(msg));

    io[0].iov_len=SIZE_HEADER; 
    io[0].iov_base= &request; 

    msg.msg_iov=io; 
    msg.msg_iovlen=1; 

    nread=recvmsg(local_info.fd_remote_process, &msg, 0); 

    if ((nread < (int)SIZE_HEADER)  || request.cookie != local_info.monitored_thread_id){ 
        DPRINT(DEBUG_INFO, "Trusted thread %ld cannot read the ARGUMEN of %d, cookie %d\n",
                syscall(SYS_gettid), request.syscall_num, request.cookie);  
        die("Failed read system call arguments"); 
    }

    DPRINT(DEBUG_INFO, ">>> Trusted threaad %d request for  %s\n",
           local_info.my_tid, syscall_names[request.syscall_num]); 

    // HANDLER 
    syscallNum = request.syscall_num; 
    syscall_table_[syscallNum].handler_trusted(local_info.fd_remote_process, &request);  
    }
  
  return SUCCESS;
}

int create_trusted_thread() 
{

  void *tls=NULL; 
  int fd_remote_process;

  fd_remote_process=
      connect_remote_process(&sandbox.connection, UNTRUSTED_THREAD,  0); 
 
  if (fd_remote_process < 0)
      die("Failed connection to remote process"); 

  if (!(tls = install_tls()))  
      die("Install TLS"); 

  DPRINT(DEBUG_INFO, "TLS installed at %p\n", tls); 

  // make up the TLS 
  set_local_tid(syscall(SYS_gettid)); 
  set_local_fd(fd_remote_process); 
  set_local_monitored(0); 

 
  if (sem_init(&binary_semaphore, 0, 0) < 0) 
      die("Semaphore initialization failed");
 
  DPRINT(DEBUG_INFO, "%s thread %d connected to the remote process over the socket %d\n", 
            get_local_monitored() ? "Trusted" : "Untrusted", 
            (int)get_local_tid(), (int)get_local_fd());

   int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
   char *stack_top = allocate_stack(STACK_SIZE) - sizeof( struct ThreadArgs);
   struct ThreadArgs *  thread_args = (struct ThreadArgs *)stack_top; 
   int rc= -1; 

   memset(thread_args, 0, sizeof(struct ThreadArgs)); 
   thread_args->untrusted_thread_tid =syscall(SYS_gettid); 
   
   rc = clone(trusted_thread, stack_top, flags, thread_args,
                 NULL, NULL, NULL);
   if ( rc  < 0) 
       die("Fallied to create trusted thread"); 
   
  // syncronisation point 
  DPRINT(DEBUG_INFO, "Waiting for the trusted thread to be ready\n");  
  
  sem_wait(&binary_semaphore); 
  sem_destroy(&binary_semaphore); 

  DPRINT(DEBUG_INFO, "Untrusted thread allow to run\n");  
 
  if(install_filter(fd_remote_process) < 0 )
      die("Install fileter error"); 

  DPRINT(DEBUG_INFO, "The trusted thread has been created\n");

  return SUCCESS; 
}

void print_thread_info(const struct thread_info * info)

{
    DPRINT(DEBUG_INFO, "%s thread %d, Monitored thread %d, Process %d, Gropu %d, Session %d\n", 
                         info->type == TRUSTED_THREAD ? "Trusted" : "Untrusted",
                         info->tid, info->monitored_thread_id, info->pid, info->gid, info->sid); 
}

int connect_remote_process( struct connection_info * info_connection, 
                            thread_type type, pid_t monitored)
{
    int sockfd = 0;
    unsigned bytes_transfered= 0;
    struct sockaddr_in serv_addr; 
    struct thread_info info; 
    char buf[ACKNOWLEDGE]={0}; 
    
    memset(&serv_addr, 0, sizeof(serv_addr)); 
    memset(&info, 0, sizeof(info)); 

    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
      die("Socket"); 
   
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(info_connection->port); 

    if(inet_pton(AF_INET, info_connection->ip, &serv_addr.sin_addr)<=0)
       die("inet_pton"); 
   
    if(connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
       die("connect"); 

    // This identify the thread 
    info.type=type; 
    info.tid=syscall(SYS_gettid); 
    info.pid=getpid();
    info.gid=getpgrp(); 
    info.sid=getsid(0);
    info.monitored_thread_id = (type == TRUSTED_THREAD ) ? monitored : 0; 
    info.cookie= (type == TRUSTED_THREAD ) ? monitored : info.tid; 
    info.visibility = sandbox.visibility; 

    // send info 
    INTR_RES(write(sockfd, (char *)&info, sizeof(info)), bytes_transfered); 

    if (bytes_transfered < sizeof(info))
        die("Write (sending thread info)"); 
    // waits for acknowledge   
    INTR_RES(read(sockfd, buf, ACKNOWLEDGE), bytes_transfered); 

    if (bytes_transfered != ACKNOWLEDGE)
        die("Read (waiting for acknowledge)"); 

    if (!strncmp(buf, ACCEPTED, sizeof(ACCEPTED)))
      return sockfd; 
    else 
      return ERROR_FUNCTION; 
}

// Allocate a stack that is never freed.
char * allocate_stack(size_t stack_size) 
{
#if defined(__i386__)
  void *stack = mmap2(NULL, stack_size, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#else
  void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#endif
  if (stack == MAP_FAILED)
      die("Map(stack)"); 

  return (char *) stack + stack_size;
}

