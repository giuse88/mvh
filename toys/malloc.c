#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h> 
#include <string.h>

#define SIZE 1024*1024 

int main()  
{
  char * buf = malloc(SIZE); 

  printf("Buff address %p\n",buf);
  memset(buf, 'A', SIZE); 
  free(buf); 
  buf=malloc(1); 
  *buf='G';
  printf("Buf addres %p, buf content %c \n", buf, *buf);
  
  return 0; 
}

  
