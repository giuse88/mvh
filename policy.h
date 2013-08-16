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
    { __NR_open,            untrusted_open,            trusted_patch },
    { __NR_openat,          untrusted_openat,          NO_HANDLER},
/*     The trusted must be included  for the close system call*/
     //because some programs close the standard file descriptors 
    { __NR_close,           DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED},
    { __NR_fstat,           untrusted_fstat,           DEFAULT_TRUSTED}, 
    { __NR_stat,            untrusted_stat_pub,        NO_HANDLER     }, 
    { __NR_getdents,        untrusted_getdents,        NO_HANDLER}, 
    { __NR_mmap,            untrusted_mmap,            DEFAULT_TRUSTED},
    { __NR_write,           untrusted_write,           DEFAULT_TRUSTED}, 
    { __NR_writev,           untrusted_writev,           DEFAULT_TRUSTED}, 
    { __NR_read,            untrusted_read,            trusted_read   }, 
    { __NR_lseek,           DEFAULT_UNTRUSTED,         NO_HANDLER     },
    { __NR_ioctl,           untrusted_ioctl,           trusted_ioctl  }, 
    //{ __NR_munmap,          DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED}, 
    { __NR_getpid,          DEFAULT_UNTRUSTED,         trusted_getpid     }, 
    { __NR_gettid,          DEFAULT_UNTRUSTED,         NO_HANDLER     }, 
    { __NR_getcwd,          untrusted_getcwd,          DEFAULT_TRUSTED}, 
    { __NR_getuid,          DEFAULT_UNTRUSTED,         NO_HANDLER     }, 
    { __NR_fcntl,           DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED},
    { __NR_socket,          DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED},  
    { __NR_bind,            untrusted_bind,            DEFAULT_TRUSTED},  
    { __NR_listen,          DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED},  
    { __NR_accept,          untrusted_accept,          trusted_accept },  
    { __NR_setsockopt,      untrusted_setsockopt,      DEFAULT_TRUSTED}, 
    { __NR_epoll_ctl,       untrusted_epoll_ctl,       DEFAULT_TRUSTED}, 
    { __NR_epoll_wait,      DEFAULT_UNTRUSTED,         trusted_epoll_wait }, 
    { __NR_sendfile,        DEFAULT_UNTRUSTED,         trusted_sendfile_pub}, 
    { __NR_clone,           untrusted_clone,           trusted_clone}, 
};

//PRIVATE APPLICATION
const struct policy private_policy[] = {
/*--------------------------------------------------------------------------------
  |SYSCALL NUM        |      UNTRUSTED THREAD    |     TRUSTED THREAD            |         
  --------------------------------------------------------------------------------  */ 
    { __NR_exit,            DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED},
    { __NR_exit_group,      DEFAULT_UNTRUSTED,         trusted_exit_group},
    { __NR_open,            untrusted_open,            trusted_open     },
    { __NR_openat,          untrusted_openat,          DEFAULT_TRUSTED},
    { __NR_fstat,           DEFAULT_UNTRUSTED,         trusted_fstat  }, 
    { __NR_stat,            untrusted_stat_priv,       trusted_stat   }, 
    { __NR_getdents,        DEFAULT_UNTRUSTED,         trusted_getdents}, 
    { __NR_mmap,            DEFAULT_UNTRUSTED,         trusted_mmap  },
    { __NR_close,           DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED},
    { __NR_write,           untrusted_write,           DEFAULT_TRUSTED}, 
    { __NR_writev,          untrusted_writev,          DEFAULT_TRUSTED}, 
    { __NR_read,            untrusted_read,             trusted_read   }, 
    { __NR_lseek,           DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED},
    { __NR_ioctl,           untrusted_ioctl,            trusted_ioctl  }, 
    //{ __NR_munmap,          DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED},
    { __NR_getpid,          DEFAULT_UNTRUSTED,          trusted_getpid}, 
    { __NR_gettid,          DEFAULT_UNTRUSTED,         NO_HANDLER     }, 
    { __NR_getcwd,          DEFAULT_UNTRUSTED,         trusted_getcwd  }, 
    { __NR_getuid,          DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED },
    { __NR_fcntl,           DEFAULT_UNTRUSTED,         DEFAULT_TRUSTED },
    { __NR_socket,          DEFAULT_UNTRUSTED,         NO_HANDLER      },
    { __NR_bind,            untrusted_bind,            NO_HANDLER      },  
    { __NR_listen,          DEFAULT_UNTRUSTED,         NO_HANDLER      },  
    { __NR_accept,          untrusted_accept,          NO_HANDLER      },  
    { __NR_setsockopt,      untrusted_setsockopt,      NO_HANDLER      }, 
    { __NR_epoll_ctl,       untrusted_epoll_ctl,       NO_HANDLER      }, 
    { __NR_epoll_wait,      untrusted_epoll_wait,      NO_HANDLER      }, 
    { __NR_sendfile,        DEFAULT_UNTRUSTED,         trusted_sendfile_priv }, 
    { __NR_clone,           untrusted_clone,            trusted_clone}, 
};
 
#endif /* end of include guard: POLICY_H */
