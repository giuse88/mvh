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

extern char * syscall_names[];

#include "linux_syscall_support.h" 

#define   __USE_GNU    1
#define   _GNU_SOURCE  1

#define STACK_SIZE 0x8000

// Semaphore to syncronize two thread
static sem_t binary_semaphore; 

long DoSyscall( syscall_request * );
asm(
    ".pushsection .text, \"ax\", @progbits\n"
    ".internal DoSyscall\n"
    ".global DoSyscall\n"
    "DoSyscall:\n"
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
void   print_syscall_info(const syscall_request * req); 


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
    syscall_request request; 
    syscall_result request_result; 
    int nread=0, nwrite=0; 

    memset(&request, 0, sizeof(request));
    memset(&request_result, 0, sizeof(request_result)); 

    /* The trusted thread is stopped here */ 
    INTR_RES(read(local_info.fd_remote_process ,
                  (char *)&request,  sizeof(request)), nread); 
   
    DPRINT(DEBUG_INFO, "TRUSTED THREAD %d %ld request for  %s\n",
           local_info.my_tid, syscall(SYS_gettid), 
           syscall_names[request.syscall_identifier]); 

    if (nread < (int)sizeof(request)) { /* || request.cookie != local_info.monitored_thread_id) */
        DPRINT(DEBUG_INFO, "Trusted thread %ld cannot read the argumnt of %ld, cookie %d\n",
                syscall(SYS_gettid), request.syscall_identifier, request.cookie);  
        die("Failed read system call arguments"); 
    }

    if ( request.syscall_identifier == __NR_exit) {
     
      int res=-1; 

      fprintf(stderr, "Exit\n"); 

/*      if ((res=kill(untrusted_tid, SIGTERM)) < 0)*/
          /*die("Error kill"); */

      DPRINT(DEBUG_INFO, "Trusted thread %d, I have terminated application %d\n", 
              local_info.my_tid, request.cookie); 
      
     
      request_result.cookie = request.cookie; 
      request_result.result = res; 

  //    INTR_RES(write(local_info.fd_remote_process,(char *)&request_result,sizeof(request_result)), nwrite); 
   
      // I should clse also the fd of the untrusted process 
      close(local_info.fd_remote_process); 
      _exit(0); 
    }
    if ( request.syscall_identifier == __NR_clone ) {
      long clone_flags = (long)   request.arg0; 
      char *stack      = (char *) request.arg1;
      int  *pid_ptr    = (int *)  request.arg2;
      int  *tid_ptr    = (int *)  request.arg3;
      void *tls_info   = (void *) request.arg4;
     
      request_result.result=clone(handle_new_thread,
                                    allocate_stack(STACK_SIZE), clone_flags,
                                    (void *)stack,pid_ptr, tls_info, tid_ptr); 

    } else {
      request_result.result = DoSyscall(&request);
    }
      request_result.cookie = request.cookie; 

    INTR_RES(write(local_info.fd_remote_process,(char *)&request_result,sizeof(request_result)), nwrite); 

    DPRINT(DEBUG_INFO, "TRUSTED_THREAD %d%ld executed syscall %s\n", local_info.my_tid, syscall(SYS_gettid),syscall_names[request.syscall_identifier]); 

    if (nwrite < (int)sizeof(request_result)) 
        die("Failed write system call arguments"); 
  }
  
  return SUCCESS;
}

int create_trusted_thread() 
{

  struct thread_local_info local_info; 
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

void fill_syscall_request(  const ucontext_t * context,
                            syscall_request * request)
{
   memset((void*)request, 0, sizeof(syscall_request)); 
 
   request->syscall_identifier = context->uc_mcontext.gregs[REG_SYSCALL]; 
   request->arg0 = context->uc_mcontext.gregs[REG_ARG0]; 
   request->arg1 = context->uc_mcontext.gregs[REG_ARG1]; 
   request->arg2 = context->uc_mcontext.gregs[REG_ARG2]; 
   request->arg3 = context->uc_mcontext.gregs[REG_ARG3]; 
   request->arg4 = context->uc_mcontext.gregs[REG_ARG4];
   request->arg5 = context->uc_mcontext.gregs[REG_ARG5]; 

   request->cookie = get_local_tid();  

/*   if (syscall_table &&*/
       /*syscall_table[request->syscall_identifier].handler != NO_HANDLER)*/
       /*syscall_table[request->syscall_identifier].handler(request , context); */
}

int send_syscall_request(const syscall_request * req) 
{
   int sent; 
   int fd = get_local_fd(); 

   INTR_RES(write( fd,(char *)req, sizeof(syscall_request)), sent); 

    if (req->has_indirect_arguments) 
      for (int i=0; i< req->indirect_arguments; i++)
          INTR_RES(write(fd,
                      (char *)req->args[i].content,req->args[i].size), sent);     
    return sent; 
}

int get_syscall_result (syscall_result * res)
{
    int received;
    int fd = get_local_fd(); 
    pid_t tid = get_local_tid(); 

    INTR_RES(read(fd, (char *)res, sizeof(syscall_result)), received); 

    if (res->cookie != tid)
        die("cookie verification failed (result)"); 

    return received; 
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

void  print_syscall_info(const syscall_request * req) 
{

    fprintf(stderr, "System call %lu:\n", req->syscall_identifier); 
    fprintf(stderr, "Arg0 %lu,\t Arg1 %lu,\t Arg2 %lu,\t Arg3 %lu,\t \
            Arg4 %lu,\tArg5 %lu \n",req->arg0,  req->arg1,\
            req->arg2, req->arg3,  req->arg4, req->arg5); 
}
