#include <asm/unistd.h> 

.global  _start
 
.text
_start:
        mov    $len, %rdx
        mov    $msg, %rsi
        mov    $1, %rdi
        mov    $__NR_write, %rax
        syscall 
 
        mov     $0, %rdi         
        mov    $__NR_exit, %rax
        syscall 

.data
msg:
        .ascii  "Hello, world!\n"
        len =   . - msg
