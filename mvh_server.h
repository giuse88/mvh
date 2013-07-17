#ifndef MVH_SERVER_H
#define MVH_SERVER_H

#include "common.h" 
#include "handler.h"
#include "color.h" 
#include "server_handler.h"
#include "trusted_thread.h" 


#define     NFDS                 4 
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


typedef enum{EMPTY_FD=0, FILE_FD, SOCKED_FD} fd_type; 

struct fd_pair{
    fd_type type;
    int private; 
    int public; 
}; 

#define MAX_FD 10 

// temporany 
struct thread_group {
    struct fd_pair fd_maps[MAX_FD]; 
    struct thread_pair public; 
    struct thread_pair private;
    struct list_head list; /* kernel's list structure */
}; 
#define SIZE_THREAD_GROUP sizeof(struct thread_group)



extern struct thread_group connection;
extern void run_mvh_server(int); 

#endif /* end of include guard: MVH_SERVER_H */
