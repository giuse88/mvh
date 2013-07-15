#define     __USE_GNU     1
#define     _GNU_SOURCE   1

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <pthread.h>
#include <assert.h> 
#include <stdbool.h> 
#include <fcntl.h> 
#include <poll.h> 

#include "sandbox.h" 
#include "common.h" 
#include "handler.h"
#include "syscall_x64.h"
#include "color.h" 
#include "trusted_thread.h" 

#define     MAX_LISTENER_SOCKET 10 
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
struct thread_group {
    void * fd_maps; 
    struct thread_pair public; 
    struct thread_pair private;
    struct list_head list; /* kernel's list structure */
}; 
#define SIZE_THREAD_GROUP sizeof(struct thread_group)

/* PRINT INFO FUNCTIONS */ 
void print_thread_info(const struct thread_info * info, int fd){
    DPRINT(DEBUG_INFO, "%s process %d, %s thread %d, Cookie %d Monitored thread %d, Group %d, Session %d\n Connected over %d\n",  
                         info->visibility == PUBLIC ? "Public" : "Private", info->pid,
                         info->type == TRUSTED_THREAD ? "Trusted" : "Untrusted",info->tid, info->cookie,
                         info->monitored_thread_id, info->gid, info->sid, fd);  
}
void print_thread_pair(const struct thread_pair * pair){
    print_thread_info(&pair->trusted, pair->trusted_fd); 
    print_thread_info(&pair->untrusted, pair->untrusted_fd); 
}
void print_thread_group(const struct thread_group * group){
    print_thread_pair(&group->public); 
    print_thread_pair(&group->private);
}
void  __print_syscall_info(const syscall_request * req, const syscall_result *res, process_visibility vis) {
    static bool first = true; 
    if(first){
      printf("%-20s%-20s%-20s%-20s%-20s%-20s%-20s%-20s%-20s\n", "Cookie", "System Call", 
                                              "Arg0", "Arg1", "Arg2", 
                                              "Arg3", "Arg4", "Arg5", "Result");  
      first=false;
    }
    
    char * color = ( vis == PUBLIC ) ? ANSI_COLOR_GREEN : ANSI_COLOR_RED; 

    printf( "%s%-20d%-20s%-20lx%-20lx%-20lx%-20lx%-20lx%-20lx%-20lx%s\n", color, req->cookie,
             syscall_names[req->syscall_identifier], 
             req->arg0,  req->arg1,req->arg2, req->arg3,  req->arg4, req->arg5, res->result,ANSI_COLOR_RESET); 
}


// foir the time being I leave the server single thread 
/*  // if the list is empty I initialize a new one*/
    /*if ( syncronisation_group_ == NULL) {*/
       /*syncronisation_group_ = malloc(sizeof( struct syncronisation_group));*/
       /*memset(syncronisation_group_, 0 , sizeof( struct syncronisation_group));*/
       /*INIT_LIST_HEAD(&syncronisation_group_->list);*/
    /*} else {*/
        /*// We are already dealing with some connection*/
        /*// the connection starts always with an untrusted thread */
        /*if ( info.type= UNTRUSTED_THREAD && (*/

    /*}*/

struct thread_group * syncronisation_group_;
struct thread_group connection;

static int make_socket_non_blocking (int sfd){
  int flags, s;

  flags = fcntl (sfd, F_GETFL, 0);
  if (flags == -1)
    die("fcntl");

  flags |= O_NONBLOCK;
  s = fcntl (sfd, F_SETFL, flags);
  if (s == -1)
      die("fcntl");

  return 0;
}
static void start_application( int fd) {
    int res =-1;
    char buf[COMMAND] = {0}; 
    
    memset(buf, 0, COMMAND); 
    strncpy(buf, START_COMMAND, sizeof(START_COMMAND)); 
   
    INTR_RES(write(fd, buf, COMMAND), res); 
    if (res < COMMAND) 
          die("start process");
}

int receive_syscall_request( int fd,  syscall_request * req) { 
    int res = -1; 
    memset(req, 0, sizeof(syscall_request)); 
    INTR_RES(read(fd, req, sizeof(syscall_request)), res);
    if ( res != sizeof(syscall_request))
        die("Failed receiving system call request"); 
   
    return res; 
}

int receive_syscall_result( int fd,  syscall_result * result) { 
    int res = -1; 
    memset(result, 0, sizeof(syscall_result)); 
    INTR_RES(read(fd, result, sizeof(syscall_result)), res);
    if ( res != sizeof(syscall_result))
        die("Failed receiving system call result"); 
    return res; 
}

// TODO refactoring this fucntion name overlaps with the function define in trusted_thread.c 
//
int __send_syscall_request( int fd, const syscall_request * req) { 
    int res = -1; 
    INTR_RES(write(fd, req, sizeof(syscall_request)), res);
    if ( res != sizeof(syscall_request))
        die("Failed sending system call request"); 
    return res; 
}

int __send_syscall_result( int fd, const syscall_result * result) { 
    int res = -1; 
    INTR_RES(write(fd, result, sizeof(syscall_result)), res);
    if ( res != sizeof(syscall_result))
        die("Failed sending system call result"); 
    return res; 
}

void  * handle_thread_pair(void * arg) {

    int fds[NFDS]={0}; 
    struct pollfd pollfds[NFDS]; 
    int res =-1; 

    fds[PUBLIC_TRUSTED]     = connection.public.trusted_fd; 
    fds[PUBLIC_UNTRUSTED]   = connection.public.untrusted_fd; 
    fds[PRIVATE_TRUSTED]    = connection.private.trusted_fd; 
    fds[PRIVATE_UNTRUSTED]  = connection.private.untrusted_fd; 
    
//    print_thread_group(&connection); 

     /*
      * I must make the socket non-blocking 
      * because I don't know from which unstrused 
      * thread I wiil receive the first request
      */ 

    memset(pollfds, 0, sizeof(pollfds)); 
    for (int i=0; i < NFDS; i++){
        make_socket_non_blocking(fds[i]); 
        printf("%d : %d\n",i, fds[i]); 
        pollfds[i].fd = fds[i]; 
        pollfds[i].events =  POLLIN; /* there is data to read */ 
    }

    printf("Public untrusted %d  private untrusted %d\n", fds[PUBLIC_UNTRUSTED],fds[PRIVATE_UNTRUSTED]);  
    printf("Public trusted   %d  private trusted   %d\n", fds[PUBLIC_TRUSTED], fds[PRIVATE_TRUSTED]);  
    
    start_application(fds[PUBLIC_UNTRUSTED]); 
    start_application(fds[PRIVATE_UNTRUSTED]); 

    bool pub_req=false, pub_res=false; 
    bool priv_req=false, priv_res=false; 
 
    do {
 
    int bytes_received=-1; 
    syscall_request private_request, public_request;
    syscall_result  private_result , public_result; 
   
    /* 
     * = Read from the untrusted sock to collect a request
     * = Send the request to the trusted therad 
     * = Read the result from the trusted thread 
     * = Send back the result to the untrusted trusted
     */ 
    
    res=poll(pollfds,NFDS,SERVER_TIMEOUT); 

    if (res == 0)
        irreversible_error("Connection Time out"); 
    else if ( res < 0 )
        die("pool"); 
    // there must be at maximun two fd ready  
    assert( res <= 2 ); 

    if (pollfds[PUBLIC_UNTRUSTED].revents) {
        pub_req = true; 
        bytes_received = receive_syscall_request(fds[PUBLIC_UNTRUSTED], &public_request); 
        DPRINT(DEBUG_INFO, "Received request %d from %d for system call < %s > over %d\n", public_request.cookie, connection.public.untrusted.tid, 
                                                                                      syscall_names[public_request.syscall_identifier], fds[PUBLIC_UNTRUSTED]);
    }

    if (pollfds[PRIVATE_UNTRUSTED].revents) {
        priv_req = true; 
        bytes_received = receive_syscall_request(fds[PRIVATE_UNTRUSTED], &private_request); 
        DPRINT(DEBUG_INFO, "Received request %d from %d for system call < %s > over %d\n", private_request.cookie, connection.private.untrusted.tid, 
                                                                                      syscall_names[private_request.syscall_identifier], fds[PRIVATE_UNTRUSTED]);
    }

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

 
    //TODO I should also verify the cookie 
    //TODO verify the system call 
   
    // forward request 
    if(pub_req && priv_req) {
        if(__send_syscall_request(fds[PUBLIC_TRUSTED], &public_request) < 0)
            die("Failed send request public trusted thread");
        if(__send_syscall_request(fds[PRIVATE_TRUSTED], &private_request) < 0)
            die("Failed send request public trusted thread");
        
        DPRINT(DEBUG_INFO, "Sent system call request "); 
        pub_req = false; 
        priv_req = false; 
    }
    
    if( pub_res && priv_res) {

        __print_syscall_info(&public_request, &public_result, PUBLIC); 
        __print_syscall_info(&private_request, &private_result, PRIVATE); 
        if(__send_syscall_result(fds[PUBLIC_UNTRUSTED], &public_result) < 0)
            die("Failed send request public trusted thread");
        if(__send_syscall_result(fds[PRIVATE_UNTRUSTED], &private_result) < 0)
            die("Failed send request public trusted thread");
       
        pub_res = false;
        priv_res = false; 
        memset(&private_result, 0, sizeof(syscall_result)); 
        memset(&public_result, 0, sizeof(syscall_result)); 
        memset(&private_request, 0, sizeof(syscall_request));   
        memset(&public_request, 0, sizeof(syscall_request));  

    }
   
    } while(ALWAYS); 

    /*syscall_result  result; */
    /*int current = (int)arg; */

    /*int bytes_transfered=-1; */

       /*puts(" --- New thread created");*/
    /*printf(" --- Index %d Trusted thread connect on %d \n", current, connections_[current].trusted_fd ); */
    /*printf(" --- Index %d Un-trusted thread connect on %d \n", current, connections_[current].untrusted_fd ); */
    
    /*while (ALWAYS) {*/

    /*// receive request */
   
           /*syscall_names[request.syscall_identifier], */
            /*connections_[current].untrusted_fd); */

    /*if (request.has_indirect_arguments) */
      /*for (int i=0; i< request.indirect_arguments; i++)*/
      /*{ */
          /*request.args[i].content= (char *)malloc(request.args[i].size+1);*/
         
          /*memset(request.args[i].content, 0, request.args[i].size+1); */
          /*char printable_buf[BUF_SIZE] = {0}; */
          /*INTR_RES(read(connections_[current].untrusted_fd,*/
                      /*(char *)request.args[i].content,request.args[i].size), bytes_transfered); */
          /*if( bytes_transfered < request.args[i].size)*/
              /*die("Error transfering indirect_arguments"); */

          /*strncpy(printable_buf, request.args[i].content, BUF_SIZE -1); */
          /*if (request.syscall_identifier == __NR_open) */
              /*printf("open(%s, 0x%x)\n", request.args[i].content, (unsigned int)request.arg1); */
          /*else if (request.syscall_identifier == __NR_write) */
              /*printf("write(%d, %s , %d)\n", (unsigned int)request.arg0, (char *)request.args[i].content, (unsigned int)request.arg2); */
           /*else if (request.syscall_identifier == __NR_read) */
              /*printf("read(%d, %s ..., %d)\n", (unsigned int)request.arg0, printable_buf, (unsigned int)request.arg2); */

      /*}*/
   /*INTR_RES(write(connections_[current].trusted_fd, (char *)&request, sizeof(request)), bytes_transfered); */

    /*if (bytes_transfered < sizeof(request))*/
        /*die("write request"); */


    /*DPRINT(DEBUG_INFO, "%d Sent system call request %d to %d over %d\n",current, request.cookie, connections_[current].trusted.tid, connections_[current].trusted_fd); */
    
    /*if(request.syscall_identifier == __NR_exit || request.syscall_identifier == __NR_exit_group ){*/
      /*result.result=0;  */
      /*__print_syscall_info(&request, &result);  */
      /*break;     */
    /*}*/

    /*// read result  */
    /*INTR_RES(read(connections_[current].trusted_fd, (char *)&result, sizeof(result)), bytes_transfered); */

    /*if (bytes_transfered < sizeof(result)) {*/
        /*DPRINT(DEBUG_INFO, "cannot read the result of %s, transfered %d cookie %d\n",*/
                /*syscall_names[request.syscall_identifier], bytes_transfered, request.cookie);  */
        /*die("Read (result)"); */
     /*} */
    
    /*DPRINT(DEBUG_INFO, "%d Received result from %d over %d\n",current,  connections_[current].trusted.tid, connections_[current].trusted_fd); */
    /*__print_syscall_info(&request, &result);  */
    

    /*// send result */
    /*INTR_RES(write(connections_[current].untrusted_fd, (char *)&result, sizeof(result)), bytes_transfered); */

    /*if (bytes_transfered < sizeof(result))*/
        /*die("Read (result)"); */

     /*if (request.has_indirect_arguments) */
      /*for (int i=0; i< request.indirect_arguments; i++)*/
      /*{ */
          /*if (request.args[i].content)*/
              /*free(request.args[i].content);*/
      /*}*/

    /*DPRINT(DEBUG_INFO, "%d Sent result %d to %d over %d\n",current, result.cookie, connections_[current].untrusted.tid, connections_[current].untrusted_fd); */
    /*DPRINT(DEBUG_INFO, "%d == END request %d for system call < %s > \n",current, request.cookie  , syscall_names[request.syscall_identifier]); */
    /*fflush(stderr); */
    /*}*/
 
  /*close(connections_[current].trusted_fd); */
  /*close(connections_[current].untrusted_fd); */

  /*DPRINT(DEBUG_INFO, "Thread %d terminated\n", current); */
  /*memset(&connections_[current], 0, sizeof( struct thread_pair)); */

  /*pthread_exit(NULL); */

  return NULL;
}

void update_thread_group(struct  thread_group *group,
                         struct thread_info * info,
                         int sockfd,
                         process_visibility visibility )
{
    struct thread_pair * pair = (visibility == PUBLIC ) ?
                                &(group->public) : &(group->private); 

    if(info->type == UNTRUSTED_THREAD) { 
          memcpy(&(pair->untrusted) ,info, SIZE_THREAD_INFO);
          pair->untrusted_fd = sockfd;
          pair->cookie = info->cookie; 
       } else  if(info->type == TRUSTED_THREAD) { 
          memcpy(&(pair->trusted) ,info, SIZE_THREAD_INFO);
          pair->trusted_fd = sockfd;
          assert(pair->cookie == info->cookie); 
      } else {
          printf("%d",info->type);
          die("Error unkown public thread"); 
    }
}

void handle_connection(int sockfd)
{

    struct thread_info info;
    int bytes_transfered = -1; 
    char buf[ACKNOWLEDGE]={0}; 
    int i; 
    pthread_t tid; 

    // get information about the untrusted process; 
    INTR_RES(read(sockfd, (char *)&info, sizeof(info)), bytes_transfered); 

    if (bytes_transfered < sizeof(info))
        die("Read (thread info)"); 

    print_thread_info(&info, sockfd); 

    strncpy(buf, ACCEPTED, sizeof(ACCEPTED));
    // send acknowledge 
    INTR_RES(write(sockfd, buf, ACKNOWLEDGE), bytes_transfered); 

    if (bytes_transfered != ACKNOWLEDGE)
        die("Read (waiting for acknowledge)"); 
 
    update_thread_group(&connection,&info, sockfd, info.visibility);  

    // all threads are connected 
  if ( connection.public.trusted_fd   && connection.public.untrusted_fd && 
       connection.private.trusted_fd  && connection.private.untrusted_fd){
       pthread_create(&tid, NULL, handle_thread_pair, NULL); 
    }
}

int run_mvh_server(int port) 
{
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr; 
    struct sockaddr_in client;
    int size_client= sizeof(struct sockaddr_in); 
   
    memset(&serv_addr, 0, sizeof(serv_addr));
    syncronisation_group_ = NULL; 

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port); 

    if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        die("Socket"); 

    /* Enable address reuse */
    int on = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
        die("SetSockOpt"); 
    
    
    if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0 )
        die("Bind"); 

    if (listen(listenfd, MAX_LISTENER_SOCKET) < 0) 
        die("Listen"); 

    while(ALWAYS)
    {
        memset((void *)&client, 0, sizeof(client));
        connfd = accept(listenfd, (struct sockaddr *) &client, (socklen_t *)&size_client); 
       
        if (connfd < 0 )
            die("Accept");
        
        DPRINT(DEBUG_INFO, "Accepted connection from %s \n", inet_ntoa(client.sin_addr));
        handle_connection(connfd);
           
    }
}
