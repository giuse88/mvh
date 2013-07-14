#ifndef SANDBOX_H
#define SANDBOX_H

#include <sys/types.h>          
#include "debug.h"

#define MAX_IP_LENGTH          256 
#define ACKNOWLEDGE             32 
#define ACCEPTED            "ACCEPTED"
#define START_COMMAND         "START" 
#define COMMAND      32 



typedef enum {ENABLE, DISABLE} sandbox_status; 
typedef enum {PRIVATE, PUBLIC, UNKNOWN} process_visibility; 

//connection info
struct connection_info
{
  char ip[MAX_IP_LENGTH]; 
  int port; 
}; 

struct sandbox_info
{ 
    /*fd of /proc/self/maps*/
    int self_maps;  
    // process   
    pid_t process; 
    // Information regarding the remote trusted process
    struct connection_info connection; 
    //Status of the sandbox
    sandbox_status status;
    // the viisibility of the prcoess 
    process_visibility visibility; 
};

// definied in the main program 
extern struct sandbox_info sandbox; 
extern int start_sandbox();

#endif /* end of include guard: SANDBOX_H */
