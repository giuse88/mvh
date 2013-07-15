#include "handler.h"
#include "common.h"
#include "tls.h"
#include "sandbox.h"
#include "bpf-filter.h"
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





/*[> HANDLERS <] */
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

/*void sys_write (syscall_request * req , const ucontext_t * context )*/
/*{*/
   /*req->has_indirect_arguments=true; */
   /*req->indirect_arguments=1;*/
   /*req->args[0].content= (char *)req->arg1; */
   /*req->args[0].size = req->arg2 ; */
   /*req->args[0].argument_number = 1;*/
/*}*/

/*void sys_read (syscall_request * req, const ucontext_t * context ){*/
   /*[>open ( char * "path", mode ) <] */
 /*//  DPRINT(DEBUG_INFO, " --READ-- System call handler\n");*/
   /*req->has_indirect_arguments=true; */
   /*req->indirect_arguments=1;*/
   /*req->args[0].content= (char *)req->arg1; */
   /*req->args[0].size = req->arg2 ; */
   /*req->args[0].argument_number = 1;*/
/*}*/

/*void sys_clone ( syscall_request *req , const ucontext_t * context) {*/

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
   
/*}*/

//Default
u64_t  untrusted_default(const ucontext_t *ctx ){
   
    int syscallNum = -1; 

    syscallNum = ctx->uc_mcontext.gregs[REG_SYSCALL];

    DPRINT(DEBUG_INFO, "Start DEFAULT handler for < %s > \n", syscall_names[syscallNum]);

    /*memset((void*)request, 0, sizeof(syscall_request)); */
 
   /*request->syscall_identifier = context->uc_mcontext.gregs[REG_SYSCALL]; */
   /*request->arg0 = context->uc_mcontext.gregs[REG_ARG0]; */
   /*request->arg1 = context->uc_mcontext.gregs[REG_ARG1]; */
   /*request->arg2 = context->uc_mcontext.gregs[REG_ARG2]; */
   /*request->arg3 = context->uc_mcontext.gregs[REG_ARG3]; */
   /*request->arg4 = context->uc_mcontext.gregs[REG_ARG4];*/
   /*request->arg5 = context->uc_mcontext.gregs[REG_ARG5]; */
   /*request->cookie = get_local_tid();  */

   DPRINT(DEBUG_INFO, " End DEFAULT handler for < %s > \n", syscall_names[syscallNum]);
   return 0; 
}

void trusted_default (const syscall_request *req){

    DPRINT(DEBUG_INFO, "DEFAULT trusted thread \n");
}
//open 
void sys_request_open(syscall_request *req, const ucontext_t * uc ){
DPRINT(DEBUG_INFO, "Open request\n");
} 

/*void fill_syscall_request(  const ucontext_t * context,*/
                            /*syscall_request * request)*/
/*{*/
  
/*[>   if (syscall_table &&<]*/
       /*[>syscall_table[request->syscall_identifier].handler != NO_HANDLER)<]*/
       /*[>syscall_table[request->syscall_identifier].handler(request , context); <]*/
/*}*/

/*int send_syscall_request(const syscall_request * req) */
/*{*/
   /*int sent; */
   /*int fd = get_local_fd(); */

   /*INTR_RES(write( fd,(char *)req, sizeof(syscall_request)), sent); */

    /*if (req->has_indirect_arguments) */
      /*for (int i=0; i< req->indirect_arguments; i++)*/
          /*INTR_RES(write(fd,*/
                      /*(char *)req->args[i].content,req->args[i].size), sent);     */
    /*return sent; */
/*}*/

/*int get_syscall_result (syscall_result * res)*/
/*{*/
    /*int received;*/
    /*int fd = get_local_fd(); */
    /*pid_t tid = get_local_tid(); */

    /*INTR_RES(read(fd, (char *)res, sizeof(syscall_result)), received); */

    /*if (res->cookie != tid)*/
        /*die("cookie verification failed (result)"); */

    /*return received; */
/*}*/


