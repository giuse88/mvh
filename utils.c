#include "utils.h"
#include "common.h" 
#include <stdlib.h> 
#include <assert.h> 
#include <sys/types.h> 
#include <sys/socket.h>
#include <unistd.h> 

int receive_result_with_extra(int fd, struct syscall_result * result, int extra_size, char * buf) { 
    
    int left = 0, transfered=0, temp=0; 
    char * ptr = NULL; 

    CLEAN_RES(result);

    // send  struct result 
    ASYNC_CALL(read(fd, result, SIZE_RESULT), temp);
    assert(temp == SIZE_RESULT); 
   
    //read buffer
    left = extra_size;
    ptr = buf;

    do { 
      temp = read(fd,ptr,left);       
      if ( temp < 0 && (errno==EAGAIN || errno == EINTR || errno == EWOULDBLOCK)) 
        continue; 
      else if ( temp < 0 )
          die("Error receiveing data recvmsg (receive_result_with_extra)"); 
      left -= temp; 
      ptr  += temp; 
      transfered += temp;
      /*fprintf(stderr,"%d\n", left);*/
    } while(left > 0); 

    assert(transfered == extra_size);

    return transfered; 
}
int send_result_with_extra(int fd, struct syscall_result * result, int extra_size, char * buf) {

    int left = 0, transfered=0, temp=0; 
    char * ptr = NULL; 

    // send  struct result 
    ASYNC_CALL(write(fd, result, SIZE_RESULT), temp);
    assert(temp == SIZE_RESULT); 
   
    //read buffer
    left = extra_size;
    ptr = buf;

    do { 
      temp = write(fd,ptr,left);       
      if ( temp < 0 && (errno==EAGAIN || errno == EINTR || errno == EWOULDBLOCK)) 
        continue; 
      else if ( temp < 0 )
          die("Error receiveing data recvmsg (receive_result_with_extra)"); 
      left -= temp; 
      ptr  += temp; 
      transfered += temp; 
      /*fprintf(stderr,"%d\n", left);*/
    } while(left > 0); 

    assert(transfered == extra_size);

    return transfered; 
}
ssize_t receive_extra(int fd , char * buf, size_t size){
 
    int left = 0, transfered=0, temp=0; 
    char * ptr = NULL; 

    //read buffer
    left = size;
    ptr = buf;

    do { 
      temp = read(fd,ptr,left);       
      if ( temp < 0 && (errno==EAGAIN || errno == EINTR || errno == EWOULDBLOCK)) 
        continue; 
      else if ( temp < 0 )
          die("Error receiveing data recvmsg (receive_result_with_extra)"); 
      left -= temp; 
      ptr  += temp; 
      transfered += temp;
      /*fprintf(stderr, "%d\n", temp); */
    } while(left > 0); 

    assert(transfered == (int)size);
    return transfered; 

} 
ssize_t send_extra  (int fd, char * buf, size_t size) {

    int left = 0, transfered=0, temp=0; 
    char * ptr = NULL; 

        //read buffer
    left = size;
    ptr = buf;

    do { 
      temp = write(fd,ptr,left);       
      if ( temp < 0 && (errno==EAGAIN || errno == EINTR || errno == EWOULDBLOCK)) 
        continue; 
      else if ( temp < 0 )
          die("Error receiveing data recvmsg (receive_result_with_extra)"); 
      left -= temp; 
      ptr  += temp; 
      transfered += temp;
      /*fprintf(stderr, "%d\n", temp); */
    } while(left > 0); 

    assert(transfered == (int)size);
    return transfered; 
} 


