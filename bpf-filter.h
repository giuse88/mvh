#ifndef _SECCOMP_BPF_H_
#define _SECCOMP_BPF_H_

#define _GNU_SOURCE 1
#define __USE_GNU 1

#include <sys/prctl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <stddef.h> 
#include <asm/unistd.h>
#include <signal.h>
#include <unistd.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <ucontext.h>

#ifdef HAVE_LINUX_SECCOMP_H
  #include <linux/seccomp.h>
#endif

#ifndef PR_SET_NO_NEW_PRIVS
  #define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef SECCOMP_MODE_FILTER

#define SECCOMP_MODE_FILTER	    2           /* uses user-supplied filter. */
#define SECCOMP_RET_KILL	      0x00000000U /* kill the task immediately */
#define SECCOMP_RET_TRAP	      0x00030000U /* disallow and force a SIGSYS */
#define SECCOMP_RET_ALLOW	      0x7fff0000U /* allow */
#define SECCOMP_RET_TRACE	      0x7ff00000U /* trace */

struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};
#endif

#ifndef SYS_SECCOMP
  #define SYS_SECCOMP 1
#endif

#ifndef PTRACE_EVENT_SECCOMP
  #define PTRACE_O_TRACESECCOMP			0x00000080
  #define PTRACE_EVENT_SECCOMP			8 // ubuntu 12.04
#endif

#define syscall_arg(_n) (offsetof(struct seccomp_data, args[_n]))
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))
#define inst_ptr (offsetof(struct seccomp_data, instruction_pointer))
#define args(i) (offsetof(struct seccomp_data, args[i]))

#if defined(__i386__)
#define REG_SYSCALL	REG_EAX
#define ARCH_NR	AUDIT_ARCH_I386
#define REG_RESULT	REG_EAX
#define REG_SYSCALL	REG_EAX
#define REG_ARG0	REG_EBX
#define REG_ARG1	REG_ECX
#define REG_ARG2	REG_EDX
#define REG_ARG3	REG_ESI
#define REG_ARG4	REG_EDI
#define REG_ARG5	REG_EBP
#define REG_PC    REG_EIP
#define REG_BASE  REG_EBP 
#define REG_STACK REG_ESP
#elif defined(__x86_64__)
#define REG_SYSCALL	REG_RAX
#define ARCH_NR	AUDIT_ARCH_X86_64
#define REG_RESULT	REG_RAX
#define REG_SYSCALL	REG_RAX
#define REG_ARG0	REG_RDI
#define REG_ARG1	REG_RSI
#define REG_ARG2	REG_RDX
#define REG_ARG3	REG_R10
#define REG_ARG4	REG_R8
#define REG_ARG5	REG_R9
#define REG_PC    REG_RIP
#define REG_BASE  REG_RBP
#define REG_STACK REG_RSP
#else
# warning "Platform does not support seccomp filter yet"
# define REG_SYSCALL	0
# define ARCH_NR	0
#endif


#define ALLOW_ARGUMENT(name, __arg_, __value_) \
    BPF_JUMP ( BPF_JMP + BPF_JEQ + BPF_K , __NR_##name , 0 ,4),\
    BPF_STMT ( BPF_LD + BPF_W + BPF_ABS , syscall_arg( __arg_ ) ),\
    BPF_JUMP ( BPF_JMP + BPF_JEQ + BPF_K , __value_, 0, 1), \
    BPF_STMT ( BPF_RET + BPF_K , SECCOMP_RET_ALLOW), \
    EXAMINE_SYSCALL
 
#define VALIDATE_ARCHITECTURE \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define EXAMINE_SYSCALL \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr)

#define ALLOW_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define KILL_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define TRACE_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE)

#define TRAP_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP)

#define KILL_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define ALLOW_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define TRAP_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRAP)

#define TRACE_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE)

int install_filter(int); 
void emulator(int nr, siginfo_t  *info, void *void_context); 

#endif /* _SECCOMP_BPF_H_ */
