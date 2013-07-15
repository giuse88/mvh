#include "handler.h"
#include "common.h"
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

   /*DPRINT(DEBUG_INFO, " --CLONE-- System call handler\n");*/

   /*char *stack = (char *)req->arg1; */
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
void sys_request_default(syscall_request * req, const ucontext_t *uc ){
    DPRINT(DEBUG_INFO, "DEFAULT request\n");
}
void sys_result_default(const syscall_request *req){ 
    DPRINT(DEBUG_INFO, "DEFAULT result\n");
}
void trusted_default (const syscall_request *req){ 
    DPRINT(DEBUG_INFO, "DEFAULT trusted thread \n");
}
//open 
void sys_request_open(syscall_request *req, const ucontext_t * uc ){
DPRINT(DEBUG_INFO, "Open request\n");
} 


