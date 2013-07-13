#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sched.h>
#include <sched.h>
#include <linux/sched.h>
#include <unistd.h> 
#include <sys/wait.h>
#include <string.h>
#include <sys/mman.h>

#define STACK_SIZE 0x10000
#define BUFSIZE 200

#define _GNU_SOURCE

void hello (){
    fprintf(stderr,"Hello word\n"); 
    _exit(0); 
}


int main()  
{

int res; 
void *stack = mmap(0, STACK_SIZE, PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  pid_t ptid, tid; 

  printf("Stack %p\n", stack + STACK_SIZE);
  memset(stack, 0, STACK_SIZE); 
 
  res= syscall(SYS_clone,CLONE_SIGHAND|CLONE_FS|CLONE_VM|CLONE_FILES,stack + STACK_SIZE, &tid,&ptid,NULL );

  if (!res)
      hello(); 

  printf("Clone result %x\n", res); 
  waitpid(-1, NULL, __WALL); 

 return 0; 
}

  
