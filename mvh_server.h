#ifndef MVH_SERVER_H
#define MVH_SERVER_H

#include "common.h" 
#include "conf.h" 
#include "handler.h"
#include "color.h" 
#include "trusted_thread.h" 
#include <poll.h>

#define     NFDS           4 
#define PUBLIC_TRUSTED     0
#define PUBLIC_UNTRUSTED   1 
#define PRIVATE_TRUSTED    2 
#define PRIVATE_UNTRUSTED  3

struct thread_pair {
    int cookie; 
    struct thread_info trusted; 
    int trusted_fd; 
    struct thread_info untrusted; 
    int untrusted_fd; 
};    
#define SIZE_THREAD_PAIR sizeof(struct thread_pair)

typedef enum{EMPTY_FD=0, FILE_FD, SOCKET_FD, POLL_FD} fd_type; 
struct fd_info{
    fd_type type;
    process_visibility visibility; 
    int fd; 
}; 

struct thread_group {
    int fds[NFDS];
    int timer; 
    struct pollfd pollfds[NFDS +1]; 
    struct thread_pair public;
    struct thread_pair private;
    struct fd_info fd_maps[MAX_FD]; 
    char * path; 
}; 
#define SIZE_THREAD_GROUP sizeof(struct thread_group)

extern struct thread_group connection;
extern void run_mvh_server(int); 

#endif /* end of include guard: MVH_SERVER_H */
