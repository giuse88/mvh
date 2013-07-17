#ifndef HANDLER_H
#define HANDLER_H

#include "common.h" 
#include <stdbool.h> 

#define CLEAN_MSG(msg) memset(msg,0, sizeof( struct msghdr))
#define CLEAN_RES(res) memset(res,0, sizeof( struct syscall_result))
#define CLEAN_REG(reg) memset(reg,0, sizeof( struct syscall_registers))
#define CLEAN_HEA(hea) memset(hea,0, sizeof( struct syscall_header))
#define CLEAN_REQ(req) memset(req,0, sizeof( struct syscall_header))

struct syscall_request{
   u64_t syscall_identifier; 
   u64_t arg0; 
   u64_t arg1; 
   u64_t arg2; 
   u64_t arg3; 
   u64_t arg4; 
   u64_t arg5; 
} __attribute__((packed));
#define SIZE_REQUEST sizeof(struct syscall_request)

struct syscall_header { 
    int syscall_num; 
    int cookie; 
    u64_t address;
    u64_t extra; 
}__attribute__((packed)) ; 
#define SIZE_HEADER sizeof( struct syscall_header)

struct syscall_result {
    u64_t result; 
    int cookie; 
    u64_t extra;
}; 
#define SIZE_RESULT sizeof( struct syscall_result) 

struct syscall_registers{ 
   u64_t arg0; 
   u64_t arg1; 
   u64_t arg2; 
   u64_t arg3; 
   u64_t arg4; 
   u64_t arg5; 
}__attribute__((packed)); 
#define SIZE_REGISTERS sizeof(struct syscall_registers)

//default
extern void trusted_default ( int fd, const  struct syscall_header *, const struct syscall_registers *); 
extern u64_t untrusted_default(const ucontext_t *); 

// IOV position for the register 
#define REG 0

#define IOV_DEFAULT 1
#define IOV_OPEN    2 
#define IOV_DEFAULT_RESULT 2

#endif /* end of include guard: HANDLER_H */
