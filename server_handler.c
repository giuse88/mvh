#include "server_handler.h"
#include "common.h"
#include <sys/syscall.h> 
#include <stdlib.h> 
#include <assert.h> 
#include <sys/types.h> 
#include <sys/socket.h>
#include "mvh_server.h" 
#include "handler.h" 
#include <pthread.h> 

#define DEFAULT_SERVER_HANDLER server_default
struct server_handler * syscall_table_server_; 

/* Useful functions */ 
void  syscall_info(const struct  syscall_header * head, const struct syscall_registers *reg, const struct  syscall_result *res, process_visibility vis) {
    static bool first = true; 
    if(first){
      printf("%-20s%-20s%-20s%-20s%-20s%-20s%-20s%-20s%-20s\n", "Cookie", "System Call", 
                                              "Arg0", "Arg1", "Arg2", 
                                              "Arg3", "Arg4", "Arg5", "Result");  
      first=false;
    }
    
    char * color = ( vis == PUBLIC ) ? ANSI_COLOR_GREEN : ANSI_COLOR_RED; 

    printf( "%s%-20d%-20s%-20lx%-20lx%-20lx%-20lx%-20lx%-20lx%-20lx%s\n", color, head->cookie,
             syscall_names[head->syscall_num], 
             reg->arg0,  reg->arg1,reg->arg2, reg->arg3,  reg->arg4, reg->arg5, res->result,ANSI_COLOR_RESET); 
}
size_t forward_syscall_request ( int fd, const struct syscall_header * header) {

    struct msghdr msg; 
    struct iovec io[1];
    int sent=-1; 

    CLEAN_MSG(&msg);     

    io[0].iov_len=SIZE_HEADER; 
    io[0].iov_base= header; 

    msg.msg_iov=io; 
    msg.msg_iovlen=1; 
    sent=sendmsg(fd, &msg, 0); 

    if ( sent < 0) 
        die("Sendmsg (Forward_syscall_request)"); 

    assert(sent == (SIZE_HEADER)); 
    return sent; 

}
size_t forward_syscall_result ( int fd, const struct syscall_result * result) {

    struct msghdr msg; 
    struct iovec io[1];
    int sent=-1; 

    CLEAN_MSG(&msg);     

    io[0].iov_len=SIZE_RESULT; 
    io[0].iov_base= result; 

    msg.msg_iov=io; 
    msg.msg_iovlen=2; 
    sent=sendmsg(fd, &msg, 0); 
    if ( sent < 0) 
        die("Sendmsg (Forward_syscall_request)"); 

    assert(sent == (SIZE_RESULT)); 
    return sent; 

}
size_t receive_syscall_registers ( int fd, struct syscall_registers * regs){
    struct iovec io[IOV_DEFAULT];
    struct msghdr msg; 
    int received =-1; 

    memset(&msg, 0, sizeof(msg)); 

    io[REG].iov_len=SIZE_REGISTERS; 
    io[REG].iov_base=regs; 
 
    msg.msg_iov=io; 
    msg.msg_iovlen=IOV_DEFAULT; 
    received = recvmsg(fd,&msg, 0); 
    
    assert(received == SIZE_REGISTERS); 
   
    if ( received < 0) 
        die("Sendmsg (Forward_syscall_request)"); 
   
    return received; 
}
size_t receive_syscall_result( int fd, struct syscall_result * res) {

    struct iovec io[IOV_DEFAULT];
    struct msghdr msg; 
    int received =-1; 

    memset(&msg, 0, sizeof(msg)); 

    io[REG].iov_len=SIZE_RESULT; 
    io[REG].iov_base=res; 
 
    msg.msg_iov=io; 
    msg.msg_iovlen=IOV_DEFAULT; 
    received = recvmsg(fd,&msg, 0); 
    
    if ( received < 0) 
        die("Sendmsg (Forward_syscall_request)"); 
   
    assert(received == SIZE_RESULT); 
    return received; 

}

/*************************** HANDLERS ******************************/ 
/*DEFUALT*/
void server_default ( int fds[] ,struct pollfd pollfds[], const struct syscall_header * public , const struct syscall_header * private) { 
 
    int bytes_received=-1; 
    struct syscall_registers public_regs, private_regs; 
    struct syscall_result public_result, private_result; 

    bool pub_req=false, pub_res=false; 
    bool priv_req=false, priv_res=false; 
    int res =-1; 
    bool completed=false; 

    DPRINT(DEBUG_INFO, "Server default handler for system call <%s>\n", syscall_names[public->syscall_num]);
   
    /* 
     * = Read from the untrusted sock to collect a request
     * = Send the request to the trusted therad 
     * = Read the result from the trusted thread 
     * = Send back the result to the untrusted trusted
     */ 
 
    if(forward_syscall_request(fds[PUBLIC_TRUSTED], public) < 0)
            die("failed send request public trusted thread");
    if(forward_syscall_request(fds[PRIVATE_TRUSTED], private) < 0)
            die("failed send request public trusted thread");
     
    DPRINT(DEBUG_INFO, "Forwarded system call requests to the respective thread\n"); 
   
    do { 

    res=poll(pollfds,NFDS,SERVER_TIMEOUT); 

    if (res == 0)
            irreversible_error("Connection Time out"); 
    else if ( res < 0 )
            die("pool"); 

   if (pollfds[PUBLIC_TRUSTED].revents) {
        pub_res=true; 
        bytes_received = receive_syscall_result(fds[PUBLIC_TRUSTED], &public_result); 
        DPRINT(DEBUG_INFO, "Received result for %d from %d over %d\n", public_result.cookie, connection.public.trusted.tid,fds[PUBLIC_TRUSTED]);
      }

    if (pollfds[PRIVATE_TRUSTED].revents) {
        priv_res = true; 
        bytes_received = receive_syscall_result(fds[PRIVATE_TRUSTED], &private_result); 
        DPRINT(DEBUG_INFO, "Received result for %d from %d over %d\n", private_result.cookie, connection.private.trusted.tid,fds[PRIVATE_TRUSTED]);
    }

 
    /*//TODO I should also verify the cookie */
   
    
    if( pub_res && priv_res) {
        syscall_info(public, &public->regs, &public_result, PUBLIC); 
        syscall_info(private,&private->regs, &private_result, PRIVATE); 
        if(forward_syscall_result(fds[PUBLIC_UNTRUSTED], &public_result) < 0)
            die("Failed send request public trusted thread");
        if(forward_syscall_result(fds[PRIVATE_UNTRUSTED], &private_result) < 0)
            die("Failed send request public trusted thread");
       
        completed = true; 
        pub_res = false;
        priv_res = false; 
        CLEAN_RES(&public_result); 
        CLEAN_RES(&private_result); 
    }
   
    } while(!completed); 

    return; 
}
/*OPEN*/
/*******************************************************************/ 

void server_open ( int fds[] ,struct pollfd pollfds[], const struct syscall_header * public , const struct syscall_header * private) {

    DPRINT(DEBUG_INFO, "Open SYSTEM CALL"); 

    // Forward system call to the private version 
    
    // get the result 
   
    //send back the result to the untrusted threads 

} 

/*EXIT GROUP*/
void server_exit_group ( int fds[] ,struct pollfd poolfds[], const struct syscall_header * public , const struct syscall_header * private) {

    server_default(fds, poolfds, public, private); 

    for ( int i=0; i< NFDS; i++)
        close(fds[i]); 
   
    memset(&connection, 0, sizeof(connection)); 
    pthread_exit(NULL); 

}

/************** INSTALL SERVER HANDLER *****************************/ 
void initialize_server_handler() { 

   static struct server_policy { 
       int syscall_num; 
       void (*handler)(int [] , struct pollfd [] ,const struct syscall_header*,const struct  syscall_header *); 
   } default_policy [] = {
        /*server handler */
      { __NR_exit_group,     server_exit_group }
   }; 


   syscall_table_server_ = (struct server_handler *)malloc( MAX_SYSTEM_CALL * (sizeof( struct server_handler))); 

  if (!syscall_table_server_) 
      die("Failed allocation memory for server handlers"); 

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

  DPRINT(DEBUG_INFO, "System call handlers installed\n"); 

} 
/*******************************************************************/ 


