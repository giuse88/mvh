#include "utils.h"
#include "common.h" 
#include <stdlib.h> 
#include <assert.h> 
#include <sys/types.h> 
#include <sys/socket.h>

int receive_result_with_extra(int fd, struct syscall_result * result, int extra_size, char * buf) { 
    struct iovec io[2];
    struct msghdr msg; 
    int transfered=0, temp=0; 
    const int total =  SIZE_RESULT + extra_size; 

    CLEAN_MSG(&msg);
    memset(io, 0, sizeof(io)); 
   
    // result header 
    io[1].iov_len=SIZE_RESULT; 
    io[1].iov_base=result;
    // result buffer
    io[0].iov_len = extra_size; 
    io[0].iov_base = buf; 
    // iov struct 
    msg.msg_iov=io;
    msg.msg_iovlen=2;
    
    do { 
      temp = recvmsg(fd,&msg, 0);       
      if ( temp < 0 && (errno==EAGAIN || errno == EINTR || errno == EWOULDBLOCK)) 
        continue; 
      else if ( temp < 0 )
          die("Error receiveing data recvmsg (receive_result_with_extra)"); 
      transfered += temp; 
    } while(transfered < total); 

    if ( transfered < 0) 
        die("recvmsg (receive_result_with_extra)"); 
    
    assert(transfered == total);
    return transfered; 
}
int send_result_with_extra(int fd, struct syscall_result * result, int extra_size, char * buf) {

    struct iovec io[2];
    struct msghdr msg; 
    int transfered=0, temp=0; 
    const int total =  SIZE_RESULT + extra_size; 

    CLEAN_MSG(&msg);
    memset(io, 0, sizeof(io)); 
    
    // result header 
    io[1].iov_len=SIZE_RESULT; 
    io[1].iov_base=result;
    // result buffer
    io[0].iov_len = extra_size; 
    io[0].iov_base = buf; 
    // iov struct 
    msg.msg_iov=io;
    msg.msg_iovlen=2;

    do {
      temp=sendmsg(fd,&msg, 0); 
      if ( temp < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
          continue; 
      else if ( temp < 0)
          die("Failed sending data ( send_result_with_extra)");  
      transfered += temp; 
    } while( transfered < total);

    if ( transfered < 0) 
        die("recvmsg (fstat handler)"); 

    assert(transfered == total);

    return transfered; 
}

ssize_t receive_extra_result(int fd , char * buf, size_t size){
  
    struct iovec io[1];
    struct msghdr msg; 
    int transfered=0, temp=0; 
    const int total =size; 
    CLEAN_MSG(&msg);
    memset(io, 0, sizeof(io)); 
    
    // result header 
    io[0].iov_len=size; 
    io[0].iov_base=buf;
    // result buffer
    msg.msg_iov=io;
    msg.msg_iovlen=1;
     
    do { 
      temp = recvmsg(fd,&msg, 0);       
      if ( temp < 0 && (errno==EAGAIN || errno == EINTR || errno == EWOULDBLOCK)) 
        continue; 
      else if ( temp < 0 )
          die("Error receiveing data recvmsg (receive_result_with_extra)"); 
      transfered += temp; 
    } while(transfered < total); 

    if ( transfered < 0) 
        die("recvmsg (receive extra result)"); 
    assert(transfered == (int)(size)); 

    return transfered; 

} 
ssize_t send_extra_result  (int fd, char * buf, size_t size) {
 
    struct iovec io[1];
    struct msghdr msg; 
    int transfered=0, temp=0; 
    const int total = size; 

    CLEAN_MSG(&msg);
    memset(io, 0, sizeof(io)); 
    
    // result header 
    io[0].iov_len=size; 
    io[0].iov_base=buf;
    // result buffer
    msg.msg_iov=io;
    msg.msg_iovlen=1;
    
    do {
      temp=sendmsg(fd,&msg, 0); 
      if ( temp < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
          continue; 
      else if ( temp < 0)
          die("Failed sending data ( send_result_with_extra)");  
      transfered += temp; 
    } while( transfered < total);

    if ( transfered < 0) 
        die("recvmsg (receive extra result)"); 
    assert(transfered == (int)(size)); 

    return transfered; 
} 


