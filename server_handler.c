#include "server_handler.h"
#include "common.h"
#include "handler.h" 
#include <sys/syscall.h> 

struct server_handler * syscall_table_server_; 

/*DEFUALT*/
void server_default ( const syscall_request * request, const syscall_request * private_request) { 
    DPRINT(DEBUG_INFO, "Server default handler\n"); 
}
#define DEFAULT_SERVER_HANDLER server_default
/*OPEN */
void sys_server_open ( const syscall_request * request, const syscall_request * private_request) {
    DPRINT(DEBUG_INFO, "Server OPEN handler\n"); 
}


/************** INSTALL SERVER HANDLER *****************************/ 
void initialize_server_handler() { 

   static struct server_policy { 
       int syscall_num; 
       void (*handler)(const syscall_request *,const syscall_request *); 
   } default_policy [] = {
        /*server handler */
       { __NR_open,     sys_server_open }
   }; 

    /*default initiailization */
    for (struct server_handler * serv_handler=syscall_table_server_; 
            serv_handler < syscall_table_server_ + MAX_SYSTEM_CALL; 
            serv_handler++)
        serv_handler->handler = DEFAULT_SERVER_HANDLER; 

    /*install policy */

  for (const struct server_policy *policy = default_policy;
       policy-default_policy < (int)(sizeof(default_policy)/sizeof(struct server_policy));
       ++policy) 
           syscall_table_server_[policy->syscall_num].handler = policy->handler; 

} 
