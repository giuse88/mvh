#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h> 
#include <pthread.h>
#include "../sandbox.h" 
#include "../common.h" 
#include "../trusted_thread.h"


#if defined (__i386__)
  #include "../syscall_x32.h"
#elif (__x86_64__)
  #include "../syscall_x64.h"
#endif 


#define __USE_GNU 1
#define _GNU_SOURCE 1
#define MAX_THREAD 10 

int first=1;

void print_thread_info(const struct thread_info * info)
{
    DPRINT(DEBUG_INFO, "Cookie %d Thread %d, Monitored thread %d, Process %d, Gropu %d, Session %d, Type %s \n",  
                         info->cookie, info->tid, info->monitored_thread_id, info->pid, info->gid, info->sid,  
                         info->type == TRUSTED_THREAD ? "Trusted" : "Untrusted");
}


void  __print_syscall_info(const syscall_request * req, const syscall_result *res) {


    if(first){
      printf("%-20s%-20s%-20s%-20s%-20s%-20s%-20s%-20s%-20s\n", "Cookie", "System Call", 
                                              "Arg0", "Arg1", "Arg2", 
                                              "Arg3", "Arg4", "Arg5", "Result");  
      first=0;
    }
     printf("%-20d%-20s%-20lx%-20lx%-20lx%-20lx%-20lx%-20lx%-20lx\n",req->cookie, syscall_names[req->syscall_identifier], 
             req->arg0,  req->arg1,req->arg2, req->arg3,  req->arg4, req->arg5, res->result); 
}


struct thread_pair {
    int cookie; 
    struct thread_info trusted; 
    int trusted_fd; 
    struct thread_info untrusted; 
    int untrusted_fd; 
};    



static struct thread_pair connections_[MAX_THREAD]; 
static int index_ =0; 


#define BUF_SIZE 10


void  * handle_thread_pair(void * arg) {
    
    syscall_request request;
    syscall_result  result; 
    int current = (int)arg; 

    int bytes_transfered=-1; 

    /* 
     * = Read from the untrusted sock to collect a request
     * = Send the request to the trusted therad 
     * = Read the result from the trusted thread 
     * = Send back the result to the untrusted trusted
     */ 
    puts(" --- New thread created");
    printf(" --- Index %d Trusted thread connect on %d \n", current, connections_[current].trusted_fd ); 
    printf(" --- Index %d Un-trusted thread connect on %d \n", current, connections_[current].untrusted_fd ); 
    
    while (1) {

    // receive request 
    INTR_RES(read(connections_[current].untrusted_fd, (char *)&request, sizeof(request)), bytes_transfered); 

    if (bytes_transfered < sizeof(request)){
        printf("Error reading from %d, bytes read %d\n", connections_[current].untrusted_fd, bytes_transfered); 
        die("Read (Untrusted thread request)"); 
    } 
    
    DPRINT(DEBUG_INFO, " %d == START request %d for system call < %s >\n", current, request.cookie, syscall_names[request.syscall_identifier]); 
    DPRINT(DEBUG_INFO, "%d Received request %d from %d for system call %s over %d\n",current, request.cookie, connections_[current].untrusted.tid,
            syscall_names[request.syscall_identifier], 
            connections_[current].untrusted_fd); 

    if (request.has_indirect_arguments) 
      for (int i=0; i< request.indirect_arguments; i++)
      { 
          request.args[i].content= (char *)malloc(request.args[i].size+1);
         
          memset(request.args[i].content, 0, request.args[i].size+1); 
          char printable_buf[BUF_SIZE] = {0}; 
          INTR_RES(read(connections_[current].untrusted_fd,
                      (char *)request.args[i].content,request.args[i].size), bytes_transfered); 
          if( bytes_transfered < request.args[i].size)
              die("Error transfering indirect_arguments"); 

          strncpy(printable_buf, request.args[i].content, BUF_SIZE -1); 
          if (request.syscall_identifier == __NR_open) 
              printf("open(%s, 0x%x)\n", request.args[i].content, (unsigned int)request.arg1); 
          else if (request.syscall_identifier == __NR_write) 
              printf("write(%d, %s , %d)\n", (unsigned int)request.arg0, (char *)request.args[i].content, (unsigned int)request.arg2); 
           else if (request.syscall_identifier == __NR_read) 
              printf("read(%d, %s ..., %d)\n", (unsigned int)request.arg0, printable_buf, (unsigned int)request.arg2); 

      }
   INTR_RES(write(connections_[current].trusted_fd, (char *)&request, sizeof(request)), bytes_transfered); 

    if (bytes_transfered < sizeof(request))
        die("write request"); 


    DPRINT(DEBUG_INFO, "%d Sent system call request %d to %d over %d\n",current, request.cookie, connections_[current].trusted.tid, connections_[current].trusted_fd); 
    
    if(request.syscall_identifier == __NR_exit || request.syscall_identifier == __NR_exit_group ){
      result.result=0;  
      __print_syscall_info(&request, &result);  
      break;     
    }

    // read result  
    INTR_RES(read(connections_[current].trusted_fd, (char *)&result, sizeof(result)), bytes_transfered); 

    if (bytes_transfered < sizeof(result)) {
        DPRINT(DEBUG_INFO, "cannot read the result of %s, transfered %d cookie %d\n",
                syscall_names[request.syscall_identifier], bytes_transfered, request.cookie);  
        die("Read (result)"); 
     } 
    
    DPRINT(DEBUG_INFO, "%d Received result from %d over %d\n",current,  connections_[current].trusted.tid, connections_[current].trusted_fd); 
    __print_syscall_info(&request, &result);  
    

    // send result 
    INTR_RES(write(connections_[current].untrusted_fd, (char *)&result, sizeof(result)), bytes_transfered); 

    if (bytes_transfered < sizeof(result))
        die("Read (result)"); 

     if (request.has_indirect_arguments) 
      for (int i=0; i< request.indirect_arguments; i++)
      { 
          if (request.args[i].content)
              free(request.args[i].content);
      }

    DPRINT(DEBUG_INFO, "%d Sent result %d to %d over %d\n",current, result.cookie, connections_[current].untrusted.tid, connections_[current].untrusted_fd); 
    DPRINT(DEBUG_INFO, "%d == END request %d for system call < %s > \n",current, request.cookie  , syscall_names[request.syscall_identifier]); 
    fflush(stderr); 
    }
 
  close(connections_[current].trusted_fd); 
  close(connections_[current].untrusted_fd); 

  DPRINT(DEBUG_INFO, "Thread %d terminated\n", current); 
  memset(&connections_[current], 0, sizeof( struct thread_pair)); 

  pthread_exit(NULL); 

  return NULL;
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

// temporaney
// This code does not free space for new threads, but 10 thread are enough
   for (i =0; i < index_ ; i++) 
       if(info.cookie == connections_[i].cookie) 
          break; 
           
   if (info.type == TRUSTED_THREAD){
      memcpy(&connections_[i].trusted,&info, sizeof(struct thread_info));
      connections_[i].trusted_fd = sockfd;
      connections_[i].cookie = info.cookie; 
   } else{
      memcpy(&connections_[i].untrusted, &info, sizeof(struct thread_info));
      connections_[i].untrusted_fd = sockfd;
      connections_[i].cookie = info.cookie; 
   }
        
  if ( connections_[i].trusted_fd>0 && connections_[i].untrusted_fd > 0){
       ++index_; 
       pthread_create(&tid, NULL, handle_thread_pair, (void *)i); 
    }
 }

int main(int argc, char *argv[])
{
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr; 
    struct sockaddr_in client;
    int size_client= sizeof(struct sockaddr_in); 

    char sendBuff[1025];

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));
    memset(sendBuff, '0', sizeof(sendBuff)); 
    memset(connections_,0 , sizeof(connections_)); 
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5555); 

    if (bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0 )
        die("Bind"); 


    if (listen(listenfd, 10) < 0) 
        die("Listen"); 

    while(1)
    {
            memset((void *)&client, 0, sizeof(client));

            connfd = accept(listenfd, (struct sockaddr *) &client, (socklen_t *)&size_client); 
           
            if ( connfd < 0 )
                die("accept");
            
            printf("Accepted connection from %s \n", inet_ntoa(client.sin_addr));

            handle_connection(connfd);
           
         }
}
