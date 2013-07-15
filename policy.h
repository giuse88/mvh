#ifndef POLICY_H
#define POLICY_H 

#include "handler.h"
#include "trusted_thread.h"

/* NO handler is executed */
#define NO_HANDLER (void*)NULL
// execute the default handler
//(i.e. it sends only the direct arguments)
#define DEFAULT    (void*)1 


struct policy {
    unsigned syscallNum;
    void     (*handler_request_untrusted)( syscall_request *, const ucontext_t *  );  
    void     (*handler_result_untrusted)( const syscall_request *);  
    void     (*handler_trusted)(const syscall_request *);  
}; 
 
 /*PUBLIC THREAD*/  
const struct policy public_policy[] = {
/*--------------------------------------------------------------------------------
  |SYSCALL NUM   | HANDLER REQUEST UNTRUSTED | RESULT UNTRUSTED | TRUSTED THREAD |         
  --------------------------------------------------------------------------------  */ 
    //{ __NR_exit,        DEFAULT, NO_HANDLER},
    //{ __NR_exit_group,  DEFAULT, NO_HANDLER},
    //{ __NR_clone ,      sys_clone, NO_HANDLER}, 
    //[>File system system calls 
  { __NR_open ,      sys_request_open,           DEFAULT,            NO_HANDLER},
  { __NR_close,      DEFAULT,                    DEFAULT,            NO_HANDLER}, 
    /*{ __NR_write,       sys_write },*/
    /*{ __NR_writev,      sys_writev}, */
    /*{ __NR_pwrite,      sys_pwrite}, */
    /*{ __NR_pread,       sys_pread }, */
    /*{ __NR_readv,       sys_readv }, */
    /*{ __NR_read,        sys_read  },*/
    /*{ __NR_llseek,      sys_llseek}, */
    /*{ __NR_readdir,     sys_readdir}, */
    /*{ __NR_getdents,    sys_getdents}, */
    /*{ __NR_truncate,    sys_truncate}, */
    /*{ __NR_chdir,       sys_chdir}, */
    /*{ __NR_mkdir,       sys_mkdir}, */
    /*{ __NR_rmdir,       sys_rmdir}, */
    /*{ __NR_rename,      sys_rename}, */
    /*{ __NR_getcwd,      sys_getcwd}, */
    /*network system calls*/ 
};

//PRIVATE APPLICATION

const struct policy private_policy[] = {
/*--------------------------------------------------------------------------------
  |SYSCALL NUM   | HANDLER REQUEST UNTRUSTED | RESULT UNTRUSTED | TRUSTED THREAD |         
  --------------------------------------------------------------------------------  */ 
  { __NR_open ,      sys_request_open,           DEFAULT,            DEFAULT},
  { __NR_close,      DEFAULT,                    DEFAULT,            DEFAULT},
};
 


#endif /* end of include guard: POLICY_H */
