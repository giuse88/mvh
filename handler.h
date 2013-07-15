#ifndef HANDLER_H
#define HANDLER_H

#include "common.h" 
#include <stdbool.h> 

typedef unsigned long register_size;

#define MAX_ARGS 1

struct indirect_argument{
    char * content; 
    size_t size;
    unsigned argument_number;
}; 
// Careful handling this structure 
// it is used to call the do system call function
typedef struct __attribute__((packed)){
   register_size syscall_identifier; 
   register_size arg0; 
   register_size arg1; 
   register_size arg2; 
   register_size arg3; 
   register_size arg4; 
   register_size arg5; 
   int cookie; 
   bool ignore;
   bool has_indirect_arguments; 
   int  indirect_arguments;
   struct indirect_argument args[MAX_ARGS]; 
} syscall_request; 
typedef struct __attribute__((packed)) {
    register_size result;
    int cookie; 
} syscall_result;

//Default
extern void trusted_default (const syscall_request *, int fd); 
extern u64_t untrusted_default(const ucontext_t *); 

#endif /* end of include guard: HANDLER_H */
