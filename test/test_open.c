#include <stdio.h>
#include <unistd.h> 
#include <sys/syscall.h> 
#include <sys/time.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, const char *argv[])
{
    struct timeval t1, t2;
    double elapsedTime;
    const char * file = "/home/giuseppe/test.c";
    int fd; 

    for ( int i=0; i < 3; i++) {

    // start timer
    gettimeofday(&t1, NULL);
    
    __asm__ ( "mov %%rbx, %%rdi\n"
              "mov %%rcx, %%rsi\n" 
              "syscall\n"
              : "=a"(fd) // output  
              : "a"(__NR_open), "b"(file),"c"(O_RDONLY) 
              : "%rdi", "%rsi" 
             );  

    // stop timer
    gettimeofday(&t2, NULL);

    // compute and print the elapsed time in millisec
    elapsedTime = (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
    elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms
    printf("Elapsed : %lf ms\n", elapsedTime); 
    close (fd);

    }

   return 0;
}
