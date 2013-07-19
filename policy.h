#ifndef POLICY_H
#define POLICY_H 

#include "handler.h"

/* NO handler is executed */

struct policy {
    unsigned syscallNum;
    u64_t     (*handler_untrusted)(const ucontext_t *  );  
    void     (*handler_trusted)(int fd, const struct syscall_header *);  
}; 

void      (*default_trusted_) (int fd, const struct syscall_header *) = trusted_default; 
u64_t     (*default_untrusted_)(const ucontext_t *) = untrusted_default; 

#define DEFAULT_UNTRUSTED  default_untrusted_
#define DEFAULT_TRUSTED    default_trusted_
#define NO_HANDLER         no_handler 

/*PUBLIC THREAD*/  
const struct policy public_policy[] = {
/*--------------------------------------------------------------------------------
  |SYSCALL NUM        |      UNTRUSTED THREAD    |     TRUSTED THREAD            |         
  --------------------------------------------------------------------------------  */ 
    { __NR_exit,            DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED},
    { __NR_exit_group,      DEFAULT_UNTRUSTED,         trusted_exit_group},
    { __NR_open,            untrusted_open,            NO_HANDLER},
    { __NR_openat,          untrusted_openat,          NO_HANDLER},
    { __NR_close,           DEFAULT_UNTRUSTED,         NO_HANDLER},
    { __NR_fstat,           untrusted_fstat,           NO_HANDLER}, 
    { __NR_getdents,        untrusted_getdents,           NO_HANDLER}, 
    { __NR_mmap,            untrusted_mmap,            DEFAULT_TRUSTED}, 
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
  |SYSCALL NUM        |      UNTRUSTED THREAD    |     TRUSTED THREAD            |         
  --------------------------------------------------------------------------------  */ 
    { __NR_exit,            DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED},
    { __NR_exit_group,      DEFAULT_UNTRUSTED,         trusted_exit_group},
    { __NR_open,            untrusted_open,            DEFAULT_TRUSTED},
    { __NR_openat,          untrusted_openat,          DEFAULT_TRUSTED},
    { __NR_fstat,           DEFAULT_UNTRUSTED,         trusted_fstat }, 
    { __NR_getdents,        DEFAULT_UNTRUSTED,         trusted_getdents }, 
    { __NR_mmap,            DEFAULT_UNTRUSTED,         trusted_mmap  },
    { __NR_close,           DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED},


};
 
#endif /* end of include guard: POLICY_H */
