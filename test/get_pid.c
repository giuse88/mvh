#include <stdio.h>
#include <unistd.h> 
#include <sys/syscall.h> 

int main(int argc, const char *argv[])
{
  printf("PID %u\n", getpid()); 
  return 0;
}
