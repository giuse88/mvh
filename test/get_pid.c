#include <stdio.h>
#include <unistd.h> 
#include <sys/syscall.h> 
#include <sys/time.h> 
#include <string.h>
#define SIZE 100

int main(int argc, const char *argv[])
{
    struct timeval t1, t2;
    double elapsedTime;
    char buf[SIZE]; 

    memset(buf, 0, SIZE); 

    /*sprintf(buf, "movq %d, %s\n syscall", SYS_getpid, "%rax");  */
    /*puts(buf); */
    
  
    /*for (int i =0; i < 5 ; i++) {*/
      
    gettimeofday(&t1, NULL);
      asm("movq $39, %rax\n"
          "syscall"); 
    gettimeofday(&t2, NULL);

    // compute and print the elapsed time in millisec
    elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
    elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms
    printf("Elapsed : %lf ms\n", elapsedTime); 
 
    /*}*/

  return 0;
}
