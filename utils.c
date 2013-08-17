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

ssize_t receive_result_with_extra_no_check(int fd, struct syscall_result * result,  char * buf, size_t extra_size) { 
    
    int left = 0, transfered=0, temp=0, transfered_result=0; 
    struct iovec io[2];
    struct msghdr msg; 
    unsigned int update =0; 


    CLEAN_RES(result);
    memset((void*)&msg, 0, sizeof(msg));  

    io[0].iov_base = result; 
    io[0].iov_len = SIZE_RESULT; 

    //read buffer
    io[1].iov_base= buf;
    io[1].iov_len = extra_size; 

    msg.msg_iov=io; 
    msg.msg_iovlen=2; 

    left = extra_size;

    do { 
    temp = recvmsg(fd, &msg, 0);    
      if ( temp < 0 && (errno==EAGAIN || errno == EINTR || errno == EWOULDBLOCK)) 
        continue; 
      else if ( temp < 0 )
          die("Error sending result  (receive_result_with_extra_no_check)"); 
      
      left -= temp; 
      transfered += temp; 
      update = ((size_t)temp < io[0].iov_len) ? 0 : 1; 
      
      io[update].iov_len -= temp; 
      io[update].iov_base += temp; 
    
     } while(left > 0); 

    assert((size_t)transfered == extra_size + SIZE_RESULT);

    return transfered + transfered_result; 
}

ssize_t send_result_with_extra(int fd, struct syscall_result * result, char * buf ,size_t extra_size) {

    int left = 0, transfered=0, temp=0, transfered_result =0; 
    struct iovec io[2];
    struct msghdr msg; 
    unsigned int update =0; 

    
    result->extra = extra_size; 
    
    memset((void*)&msg, 0, sizeof(msg));  
    
    io[0].iov_base = result; 
    io[0].iov_len = SIZE_RESULT; 

    //read buffer
    io[1].iov_base= buf;
    io[1].iov_len = extra_size; 

    msg.msg_iov=io; 
    msg.msg_iovlen=2; 
   
    left = extra_size; 
    
    do { 
    temp = sendmsg(fd, &msg, 0);    
      if ( temp < 0 && (errno==EAGAIN || errno == EINTR || errno == EWOULDBLOCK)) 
        continue; 
      else if ( temp < 0 )
          die("Error sending result  (send_result_with_extra)"); 
      
      left -= temp; 
      transfered += temp; 
      update = ((size_t)temp < io[0].iov_len) ? 0 : 1; 

      io[update].iov_len -= temp; 
      io[update].iov_base += temp; 
    
     } while(left > 0); 

    assert((size_t)transfered == extra_size + SIZE_RESULT);

    return transfered + transfered_result; 
}

ssize_t receive_extra(int fd , char * buf, size_t size){
 
    int left = 0, transfered=0, temp=0; 
    char * ptr = NULL; 

#ifdef PERFORMANCE 
  struct timeval time1, time2;
  double elapsedTime = 0; 
  gettimeofday(&time1, NULL);    
#endif 


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
 
#ifdef PERFORMANCE 
  gettimeofday(&time2, NULL);
  elapsedTime = (time2.tv_sec - time1.tv_sec) * 1000.0;      // sec to ms
  elapsedTime += (time2.tv_usec - time1.tv_usec) / 1000.0;   // us to ms
  DPRINT(DEBUG_ALL, " %d Extra elapsed : %lf ms\n",fd,  elapsedTime); 
#endif 

 
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

   if ((received =receive_extra(priv_fd, priv_buf,size)) < 0)
          die("Failed receiveing extra argument from private application"); 
    assert((size_t)received == size);
    received=0; 
    if ((received=receive_extra(pub_fd, pub_buf,size)) < 0)
          die("Failed receiveing extra argument from public application"); 
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
