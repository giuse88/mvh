#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h> 

int main()  
{

  int end  = brk(NULL); 

  printf("Program break %d\n", end);

  return 0; 
}

  
