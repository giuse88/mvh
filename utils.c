#include "utils.h"
#include "common.h" 
#include <stdlib.h> 
#include <assert.h> 
#include <sys/types.h> 
#include <sys/socket.h>
#include <unistd.h> 
#include <termios.h>
#include <sys/ioctl.h> 


ssize_t receive_result_with_extra(int fd, struct syscall_result * result,  char * buf, size_t extra_size) { 
    
    int left = 0, transfered=0, temp=0, transfered_result=0; 
    char * ptr = NULL; 

    CLEAN_RES(result);

    ASYNC_CALL(read(fd, result, SIZE_RESULT), transfered_result);
    assert(transfered_result == SIZE_RESULT); 

    left = extra_size;
    ptr = buf;

    if (!result->extra) {
        DPRINT(DEBUG_INFO, "------ EXTRA NOT COPIED\n"); 
        return transfered_result;
    }

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

    assert((size_t)transfered == extra_size);

    return transfered + transfered_result; 
}
ssize_t send_result_with_extra(int fd, struct syscall_result * result, char * buf ,size_t extra_size) {

    int left = 0, transfered=0, temp=0, transfered_result =0; 
    char * ptr = NULL; 


    result->extra = extra_size; 
    // send  struct result 
    ASYNC_CALL(write(fd, result, SIZE_RESULT), transfered_result);
    assert(transfered_result == SIZE_RESULT); 
   
    //read buffer
    left = extra_size;
    ptr = buf;

        do { 
    /*fprintf(stderr,"%d\n", left);*/
      temp = write(fd,ptr,left);       
    /*fprintf(stderr,"%d %d\n", left, temp);*/
      if ( temp < 0 && (errno==EAGAIN || errno == EINTR || errno == EWOULDBLOCK)) 
        continue; 
      else if ( temp < 0 )
          die("Error sending result  (send_result_with_extra)"); 
      left -= temp; 
      ptr   += temp; 
      transfered += temp; 
      /*fprintf(stderr,"%d\n", left);*/
    } while(left > 0); 

    assert((size_t)transfered == extra_size);

    return transfered + transfered_result; 
}
ssize_t receive_extra(int fd , char * buf, size_t size){
 
    int left = 0, transfered=0, temp=0; 
    char * ptr = NULL; 

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
ssize_t get_extra_arguments( int pub_fd , char* pub_buf, int priv_fd, char * priv_buf, size_t size){
    ssize_t received =0; 

    if ((received=receive_extra(pub_fd, pub_buf,size)) < 0)
          die("Failed receiveing extra argument from public application"); 
    assert((size_t)received == size);
    received=0; 
    if ((received =receive_extra(priv_fd, priv_buf,size)) < 0)
          die("Failed receiveing extra argument from private application"); 
    assert((size_t)received == size);
    return received; 
}
size_t get_size_from_cmd(int request) { 
  // ugly 
  switch (request) {
     case  TCGETS:
    /*0x00005401   TCGETS           struct termios * */
        return sizeof(struct termios); 
    case  FIONREAD : 
    /*FIONREAD         int **/
        return sizeof(int );
    case TIOCGWINSZ:
        return sizeof(struct winsize);
    default : 
      return 0; 
  }
}
