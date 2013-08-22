#include <stdio.h>
#include <string.h>

char shell_code[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

char exit_code[]= "\x48\x31\xc0\x48\x31\xff\xb0\x3c\x0f\x05\x90\x90"; 

char hello_code[] = 
  "\xeb\x20"   
  "\x48\x31\xc0"
  "\x48\x31\xff" 
  "\x48\x31\xf6"
  "\x48\x31\xd2"            
  "\xfe\xc0"  
 	"\x48\xff\xc7"
  "\x5e" 
  "\xb2\x0e"    //             	mov    $0xe,%dl
  "\x0f\x05"    //              	syscall 
  "\x48\x31\xc0"   //           	xor    %rax,%rax
  "\x48\x31\xff"      //       	xor    %rdi,%rdi
  "\xb0\x3c"          //      	mov    $0x3c,%al
  "\x0f\x05"           //      	syscall 
  "\xe8\xdb\xff\xff\xff"  //       	callq  4004f6 <start>
  "\x48" //tmp                 	rex.W
  "\x65"  //                	gs
  "\x6c"    //              	insb   (%dx),%es:(%rdi)
  "\x6c"      //            	insb   (%dx),%es:(%rdi)
  "\x6f"        //           	outsl  %ds:(%rsi),(%dx)
  "\x2c\x20"      //          	sub    $0x20,%al
  "\x77\x6f"        //        	ja     400599 <__libc_csu_init+0x69>
  "\x72\x6c"         //       	jb     400598 <__libc_csu_init+0x68>
  "\x64\x21\x0a"     //        	and    %ecx,%fs:(%rdx)
  "\x90"; //

  int main() {

  char *code = hello_code; 
  printf("len:%ld bytes\n", (long int)strlen(code));
    (*(void(*)()) code)();
    return 0;
}
