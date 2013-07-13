#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <pthread.h> 
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h> 

int main()  
{
  pthread_t producer_thread; 
  void *producer();
  int *ret; 


  printf("My PID %lu, my TID %lu\n",syscall(SYS_getpid), syscall(SYS_gettid)); 
  printf("Thread ID from pthread %lu\n", pthread_self()); 
  
  pthread_create(&producer_thread,NULL,producer,NULL);
  pthread_join(producer_thread,(void **)&ret);
  
  printf("Thread exit %d\n",*ret); 
  _exit(0); 
}

void *producer()
{
  int *ret = (int *)malloc(sizeof(int)); 
  printf("I'm Thread\n");
  printf("My PID %lu, my TID %lu\n",syscall(SYS_getpid), syscall(SYS_gettid)); 
  printf("Thread ID from pthread %lu\n", pthread_self()); 
  return ret; 
}

