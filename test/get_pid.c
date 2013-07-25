#include <stdio.h>
#include <unistd.h> 
#include <sys/syscall.h> 

int main(int argc, const char *argv[])
{
  printf("PID %ld\n", syscall(__NR_getpid)); 
  return 0;
}
