#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <pthread.h>
#include "sandbox.h" 
#include "common.h" 
#include "trusted_thread.h"
#include "syscall_x64.h"
#include <assert.h> 
#include <stdbool.h> 

#define     __USE_GNU     1
#define     _GNU_SOURCE   1

#define     MAX_LISTENER_SOCKET 10 

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
void print_thread_info(const struct thread_info * info){
    DPRINT(DEBUG_INFO, "%s process %d, %s thread %d, Cookie %d Monitored thread %d, Group %d, Session %d\n",  
                         info->visibility == PUBLIC ? "Public" : "Private", info->pid,
                         info->type == TRUSTED_THREAD ? "Trusted" : "Untrusted",info->tid, info->cookie,
                         info->monitored_thread_id, info->gid, info->sid);  
}
void print_thread_pair(const struct thread_pair * pair){
    print_thread_info(&pair->trusted); 
    print_thread_info(&pair->untrusted); 
}
void print_thread_group(const struct thread_group * group){
    print_thread_pair(&group->public); 
    print_thread_pair(&group->private);
}
void  __print_syscall_info(const syscall_request * req, const syscall_result *res) {
    static bool first = true; 
    if(first){
      printf("%-20s%-20s%-20s%-20s%-20s%-20s%-20s%-20s%-20s\n", "Cookie", "System Call", 
                                              "Arg0", "Arg1", "Arg2", 
                                              "Arg3", "Arg4", "Arg5", "Result");  
      first=false;
    }
     printf("%-20d%-20s%-20lx%-20lx%-20lx%-20lx%-20lx%-20lx%-20lx\n",req->cookie,
             syscall_names[req->syscall_identifier], 
             req->arg0,  req->arg1,req->arg2, req->arg3,  req->arg4, req->arg5, res->result); 
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

struct thread_group connection; void  * handle_thread_pair(void * arg) {
   

    print_thread_group(&connection); 

    /*syscall_request request;*/
    /*syscall_result  result; */
    /*int current = (int)arg; */

    /*int bytes_transfered=-1; */

    /* 
     * = Read from the untrusted sock to collect a request
     * = Send the request to the trusted therad 
     * = Read the result from the trusted thread 
     * = Send back the result to the untrusted trusted
     */ 
    /*puts(" --- New thread created");*/
    /*printf(" --- Index %d Trusted thread connect on %d \n", current, connections_[current].trusted_fd ); */
    /*printf(" --- Index %d Un-trusted thread connect on %d \n", current, connections_[current].untrusted_fd ); */
    
    /*while (1) {*/

    /*// receive request */
    /*INTR_RES(read(connections_[current].untrusted_fd, (char *)&request, sizeof(request)), bytes_transfered); */

    /*if (bytes_transfered < sizeof(request)){*/
        /*printf("Error reading from %d, bytes read %d\n", connections_[current].untrusted_fd, bytes_transfered); */
        /*die("Read (Untrusted thread request)"); */
    /*} */
    
    /*DPRINT(DEBUG_INFO, " %d == START request %d for system call < %s >\n", current, request.cookie, syscall_names[request.syscall_identifier]); */
    /*DPRINT(DEBUG_INFO, "%d Received request %d from %d for system call %s over %d\n",current, request.cookie, connections_[current].untrusted.tid,*/
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
          memcpy(&(pair->trusted) ,info, SIZE_THREAD_INFO);
          pair->trusted_fd = sockfd;
          pair->cookie = info->cookie; 
       } else  if(info->type == TRUSTED_THREAD) { 
          memcpy(&(pair->untrusted) ,info, SIZE_THREAD_INFO);
          pair->untrusted_fd = sockfd;
          assert(pair->cookie == info->cookie); 
      } else {
          printf("%d",info->type);
          die("Error unkown public thread"); 
    }
}

void handle_connection(int sockfd){

    struct thread_info info;
    int bytes_transfered = -1; 
    char buf[ACKNOWLEDGE]={0}; 
    int i; 
    pthread_t tid; 

    // get information about the untrusted process; 
    INTR_RES(read(sockfd, (char *)&info, sizeof(info)), bytes_transfered); 

    if (bytes_transfered < sizeof(info))
        die("Read (thread info)"); 

    print_thread_info(&info); 

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
