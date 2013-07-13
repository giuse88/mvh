#include <stdio.h>
#include <asm/unistd.h> 
#include <linux/types.h> 
#include <unistd.h> 
#include <sys/syscall.h> 

#define _GNU_SOURCE  1    
#define _for_(x_, y_) { int __i; for(__i=0; __i < x_ ; __i++) y_;}  

void function()
{
    
    int  ret;
  
    printf("Function address: start %p end %p\n", function, &&ret);  


    __asm__ volatile
    (
        "movl $39, %%eax\n\t"
        "syscall"
        : "=a"(ret)
        : 
        : "%rdi", "%rsi", "%rdx", "%rcx", "%r11"
    );

    printf("My pid is %d\n",ret); 

ret:  return; 
}

int main(void)
{

   _for_(10,function()); 


    return 0;
}
