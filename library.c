
#include "library.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdarg.h>
//#include <sys/mman.h>
//#include <sys/ptrace.h>
//#include <sys/resource.h>
//#include <sys/stat.h>
//#include <sys/socket.h>
//#include <sys/types.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <stdint.h> 

#include "abstract_data/compiler.h"
#include "abstract_data/list.h"
#include "abstract_data/jhash.h"
#include "abstract_data/kernel.h"
#include "abstract_data/list.h"
#include "abstract_data/rbtree.h"
#include "common.h"
#include "mmalloc.h"
#include "sandbox.h"
#include "syscall_entrypoint.h"
#include "x86_decoder.h"

#if defined(__x86_64__)
typedef Elf64_Phdr    Elf_Phdr;
typedef Elf64_Rela    Elf_Rel;

typedef Elf64_Half    Elf_Half;
typedef Elf64_Word    Elf_Word;
typedef Elf64_Sword   Elf_Sword;
typedef Elf64_Xword   Elf_Xword;
typedef Elf64_Sxword  Elf_Sxword;
typedef Elf64_Off     Elf_Off;
typedef Elf64_Section Elf_Section;
typedef Elf64_Versym  Elf_Versym;
#elif defined(__i386__)
typedef Elf32_Phdr    Elf_Phdr;
typedef Elf32_Rel     Elf_Rel;

typedef Elf32_Half    Elf_Half;
typedef Elf32_Word    Elf_Word;
typedef Elf32_Sword   Elf_Sword;
typedef Elf32_Xword   Elf_Xword;
typedef Elf32_Sxword  Elf_Sxword;
typedef Elf32_Off     Elf_Off;
typedef Elf32_Section Elf_Section;
typedef Elf32_Versym  Elf_Versym;
#else
#error Unsupported target platform
#endif

char *__kernel_vsyscall;
char *__kernel_sigreturn;
char *__kernel_rt_sigreturn;

// TODO read this value at the start of the program via getpagesize 
#define PAGE_SIZE 4096 

#define GET_PAGE_ADDRESS(x) (uintptr_t)x & ~(PAGE_SIZE-1) 

#define rb_entry_region(node) rb_entry((node), struct region, rb_region)


struct branch_target {
  char *addr;
  struct rb_node rb_target;
};

#define rb_entry_target(node) rb_entry((node), struct branch_target, rb_target)

static inline struct branch_target *rb_search_target(struct rb_root *root, char *addr) {
  struct rb_node * n = root->rb_node;
  struct branch_target *target;

  while (n) {
    target = rb_entry_target(n);

    if (addr < target->addr)
      n = n->rb_left;
    else if (addr > target->addr)
      n = n->rb_right;
    else
      return target;
  }
  return NULL;
}

/**
 * Returns a pointer pointing to the first target whose address does not compare less than @p addr
 */
static inline struct branch_target *rb_lower_bound_target(struct rb_root *root, char *addr) {
  struct rb_node *n = root->rb_node;
  struct rb_node *parent = NULL;
  struct branch_target *target;

  while (n) {
    target = rb_entry_target(n);

    if (!(target->addr < addr)) {
      parent = n;
      n = n->rb_left;
    } else
      n = n->rb_right;
  }
  return parent ? rb_entry_target(parent) : NULL;
}

/**
 * Returns an iterator pointing to the first target whose address compares greater than @p addr
 */
static inline struct branch_target *rb_upper_bound_target(struct rb_root *root, char *addr) {
  struct rb_node *n = root->rb_node;
  struct rb_node *parent = NULL;
  struct branch_target *target;

  while (n) {
    target = rb_entry_target(n);

    if (target->addr > addr) {
      parent = n;
      n = n->rb_left;
    } else
      n = n->rb_right;
  }
  return parent ? rb_entry_target(parent) : NULL;
}

static inline struct branch_target *__rb_insert_target(struct rb_root *root, char *addr, struct rb_node *node) {
  struct rb_node **p = &root->rb_node;
  struct rb_node *parent = NULL;
  struct branch_target *target;

  while (*p) {
    parent = *p;
    target = rb_entry(parent, struct branch_target, rb_target);

    if (addr < target->addr)
      p = &(*p)->rb_left;
    else if (addr > target->addr)
      p = &(*p)->rb_right;
    else
      return target;
  }

  rb_link_node(node, parent, p);

  return NULL;
}

static inline struct branch_target *rb_insert_target(struct rb_root *root, char *addr, struct rb_node *node) {
  struct branch_target *ret;
  if ((ret = __rb_insert_target(root, addr, node)))
    goto out;
  rb_insert_color(node, root);
out:
  return ret;
}

void make_writable(void * addr , bool state) {

   if (mprotect(addr, PAGE_SIZE, PROT_EXEC |  PROT_READ | ( state ? PROT_WRITE : 0)) == -1)
           die("mprotect"); 

}


bool is_safe_insn(unsigned short insn) {
  /* Check if the instruction has no unexpected side-effects. If so, it can
     be safely relocated from the function that we are patching into the
     out-of-line scratch space that we are setting up. This is often necessary
     to make room for the JMP into the scratch space. */
  return ((insn & 0x7) < 0x6 && (insn & 0xF0) < 0x40
          /* ADD, OR, ADC, SBB, AND, SUB, XOR, CMP */) ||
         #if defined(__x86_64__)
         insn == 0x63 /* MOVSXD */ ||
         #endif
         (insn >= 0x80 && insn <= 0x8E /* ADD, OR, ADC,
         SBB, AND, SUB, XOR, CMP, TEST, XCHG, MOV, LEA */) ||
         (insn == 0x90) || /* NOP */
         (insn >= 0xA0 && insn <= 0xA9) /* MOV, TEST */ ||
         (insn >= 0xB0 && insn <= 0xBF /* MOV */) ||
         (insn >= 0xC0 && insn <= 0xC1) || /* Bit Shift */
         (insn >= 0xD0 && insn <= 0xD3) || /* Bit Shift */
         (insn >= 0xC6 && insn <= 0xC7 /* MOV */) ||
         (insn == 0xF7) /* TEST, NOT, NEG, MUL, IMUL, DIV, IDIV */ ||
         (insn >= 0xF19 && insn <= 0xF1F) /* long NOP */;
}


/*It allocates a scratch page */ 

/* Temporany hack, we use a global variable to keep track of the 
 * newly  created page
 */ 

char * extra_space=NULL; 
int extra_len=-1; 

char *alloc_scratch_space(char *near, int needed) {

  if (needed > extra_len || labs(extra_space - (char *)(near)) > (1536 << 20)) {
    // Start a new scratch page and mark any previous page as write-protected
    // either the free space is not enough or if the instruction is to 
    // far  
    // TODO protect the other pages, make them read_only 
    extra_len = 4096;
    extra_space = maps_alloc_near(near, extra_len, PROT_READ | PROT_WRITE | PROT_EXEC);
    DPRINT(DEBUG_INFO, "=====> New scratch page allocated at the address %p \n", extra_space); 
  }
  if (extra_space) {
    extra_len -= needed;
    return extra_space + extra_len;
  }
  irreversible_error("Insufficient space to intercept system call");
}

void patch_syscalls_in_func(char *start, char *end) {
  
  struct rb_root branch_targets = RB_ROOT;

  for (char *ptr = start; ptr < end;) {
    unsigned short insn = next_inst((const char **)&ptr, \
            __WORDSIZE == 64, NULL, NULL, NULL, NULL, NULL);
    char *addr;
    if ((insn >= 0x70 && insn <= 0x7F) || insn == 0xEB ) {
      addr = ptr + ((signed char *)(ptr))[-1];
    } else if (insn == 0xE8 || insn == 0xE9   ||
               (insn >= 0x0F80 && insn <= 0x0F8F) ) {
      addr = ptr + ((int *)(ptr))[-1];
    } else
      continue;

    struct branch_target *target = mmalloc(sizeof(*target));
    rb_init_node(&target->rb_target);
    target->addr = addr;
    rb_insert_target(&branch_targets, addr, &target->rb_target);
  }

  struct code {
    char *addr;
    int len;
    unsigned short insn;
    bool is_ip_relative;
  } code[5] = { { 0 } };

  int i = 0;

  DPRINT(DEBUG_INFO, "Withing patch function, start %p - end %p\n", start, end); 

  for (char *ptr = start; ptr < end;) {
  
    // start cycle

    /*// Keep a ring-buffer of the last few instruction in order to find the correct place to patch the code.*/
    char *mod_rm;
    code[i].addr = ptr;
    code[i].insn = next_inst((const char **)&ptr, __WORDSIZE == 64, 0, 0, &mod_rm, 0, 0);
    code[i].len = ptr - code[i].addr;
    code[i].is_ip_relative = mod_rm && (*mod_rm & 0xC7) == 0x5;

    // Whenever we find a system call, we patch it with a jump to out-of-line
    // code that redirects to our system call entrypoint.
    
//  DPRINT(DEBUG_ALL, "Instrcution 0x%x\n", code[i].insn); 

    bool is_indirect_call=false; 
    bool is_syscall = true;
#if defined(__x86_64__)
    if (code[i].insn == 0x0F05 /* SYSCALL */  ) {
        is_syscall = true; 

#elif defined(__i386__)
    bool is_gs_call = false;
    if (code[i].len  == 7 &&
        code[i].insn == 0xFF &&
        code[i].addr[2] == '\x15' /* CALL (indirect) */ &&
        code[i].addr[0] == '\x65' /* %gs prefix */) {
      char* target;
      asm volatile("mov %%gs:(%1), %0\n"
                   : "=a"(target)
                   : "c"(*(int *)(code[i].addr + 3)));
      if (target == __kernel_vsyscall) {
        is_gs_call = true;
      }
    }
    if (is_gs_call ||
        (code[i].insn == 0xCD &&
         code[i].addr[1] == '\x80' /* INT $0x80 */ )) {
#else
  #error Unsupported target platform
#endif
      /* Found a system call. Search backwards to figure out how to redirect
         the code. We will need to overwrite a couple of instructions and,
         of course, move these instructions somewhere else.
      */ 

      DPRINT(DEBUG_INFO, "Found system call instruction at : 0x%p\n", code[i].addr); 
 

      int startInd = i; // current instruction 
      int length = code[i].len;
      
      for (int j = i;
            (j = (j + (sizeof(code) / sizeof(struct code)) - 1) %
            (sizeof(code) / sizeof(struct code))) != i; ) 
        {
       struct branch_target *target = rb_upper_bound_target(&branch_targets, code[j].addr);
        
        if (target && target->addr < ptr) {
          // Found a branch pointing to somewhere past our instruction. This
          // instruction cannot be moved safely. Leave it in place.
          break;
        }
        if (code[j].addr && !code[j].is_ip_relative  && is_safe_insn(code[j].insn)) {
         /*//  These are all benign instructions with no side-effects and no*/
         /*//  dependency on the program counter. We should be able to safely*/
         /*//  relocate them.*/
          startInd = j;
          length = ptr - code[startInd].addr;
        } else {
          break;
        }
      }

      // Search forward past the system call, too. Sometimes, we can only find
      // relocatable instructions following the system call.
#if defined(__i386__)
find_end:
#endif
    
      char *next = ptr;
      for (int j = i;
           next < end &&
           (j = (j + 1) % (sizeof(code) / sizeof(struct code))) != startInd;
           ) {
        struct branch_target *target = rb_lower_bound_target(&branch_targets, next);
        if (target && target->addr == next) {
          // Found branch target pointing to our instruction
          break;
        }
        char *tmp_rm;
        code[j].addr = next;
        code[j].insn = next_inst((const char **)&next, __WORDSIZE == 64, 0, 0, &tmp_rm, 0, 0);
        code[j].len = next - code[j].addr;
        code[j].is_ip_relative = tmp_rm && (*tmp_rm & 0xC7) == 0x5;
        if (!code[j].is_ip_relative && is_safe_insn(code[j].insn)) {
          length = next - code[startInd].addr;
        } else {
          break;
        }
      }
         
      if (length < (__WORDSIZE == 32 ? 6 : 5))
         DPRINT(DEBUG_WARNING, "Cannot intercept a system call\n"); 

      int needed = (__WORDSIZE == 32 ? 6 : 5) - code[i].len;
      int first = i;
  

      DPRINT(DEBUG_INFO, " To patch this instructionmI need %d additional bytes\n", needed); 
 
      while (needed > 0 && first != startInd) {
        first = (first + (sizeof(code) / sizeof(struct code)) - 1) %
                (sizeof(code) / sizeof(struct code));
        needed -= code[first].len;
      }
      int second = i;
      while (needed > 0) {
        second = (second + 1) % (sizeof(code) / sizeof(struct code));
        needed -= code[second].len;
      }
      int preamble = code[i].addr - code[first].addr;
      int postamble = code[second].addr + code[second].len -
                      code[i].addr - code[i].len;

      DPRINT(DEBUG_INFO, " Preamble   %d bytes\n", preamble); 
      DPRINT(DEBUG_INFO, " Postamble  %d bytes\n", postamble); 
  

//       The following is all the code that construct the various bits of
//       assembly code.

#if defined(__x86_64__)
      if (is_indirect_call)
        needed = 52 + preamble + code[i].len + postamble;
      else
        needed = 52 + preamble + postamble;
#elif defined(__i386__)
      needed = 22 + preamble + postamble;
#else
#error Unsupported target platform
#endif

      // Allocate scratch space and copy the preamble of code that was moved
      // from the function that we are patching.
      // we need addr to look for so close place  where to locate the new 
      // code. 
      
      char* dest = alloc_scratch_space(code[first].addr, needed);
      
      DPRINT(DEBUG_INFO, "%d bytes has been allocated at %p\n",needed, dest); 
    

      memset(dest, 0, needed); 

      // copy preamble 
      
      memcpy(dest, code[first].addr, preamble);

      // For jumps from the VDSO to the VSyscalls we sometimes allow exactly
      // one IP relative instruction in the preamble.
      if (code[first].is_ip_relative) {
        *(int *)(dest + (code[i].addr - code[first].addr) - 4)
          -= dest - code[first].addr;
          
        DPRINT(DEBUG_INFO, "Allowing to realocate a ip-relative instruction\n",needed, dest); 
      }

      /*
       * TODO Support indirect call 
      // For indirect calls, we need to copy the actual CALL instruction and*/
      /*// turn it into a PUSH instruction.*/
/*#if defined(__x86_64__)*/
      /*if (is_indirect_call) {*/
        /*memcpy(dest + preamble,*/
            /*"\xE8\x00\x00\x00\x00"        // CALL .*/
            /*"\x48\x83\x04\x24",           // ADDQ $.., (%rsp)*/
            /*9);*/
        /*dest[preamble + 9] = code[i].len + 42;*/
        /*memcpy(dest + preamble + 10, code[i].addr, code[i].len);*/

        /*// Convert CALL -> PUSH*/
        /*dest[preamble + 10 + (mod_rm - code[i].addr)] |= 0x20;*/
        /*preamble += 10 + code[i].len;*/
      /*}*/
/*#endif*/


      // Copy the static body of the assembly code.
      memcpy(dest + preamble,
#if defined(__x86_64__)
          is_indirect_call ?
          "\x48\x81\x3C\x24\x00\x00\x00\xFF"// CMPQ $0xFFFFFFFFFF000000,0(rsp)
          "\x72\x10"                        // JB   . + 16
          "\x81\x2C\x24\x00\x00\x00\x00"    // SUBL ..., 0(%rsp)
          "\xC7\x44\x24\x04\x00\x00\x00\x00"// MOVL $0, 4(%rsp)
          "\xC3"                            // RETQ
          "\x48\x87\x04\x24"                // XCHG %rax, (%rsp)
          "\x48\x89\x44\x24\x08"            // MOV  %rax, 8(%rsp)
          "\x58"                            // POP  %rax
          "\xC3" :                          // RETQ
          "\x48\x81\xEC\x80\x00\x00\x00"    // SUB  $0x80, %rsp
          "\x50"                            // PUSH %rax
          "\x48\x8D\x05\x00\x00\x00\x00"    // LEA  ...(%rip), %rax
          "\x50"                            // PUSH %rax
          "\x48\xB8\x00\x00\x00\x00\x00"    // MOV $syscall_enter_with_frame,
          "\x00\x00\x00"                    //     %rax
          "\x50"                            // PUSH %rax
          "\x48\x8D\x05\x06\x00\x00\x00"    // LEA  6(%rip), %rax
          "\x48\x87\x44\x24\x10"            // XCHG %rax, 16(%rsp)
          "\xC3"                            // RETQ
          "\x48\x81\xC4\x80\x00\x00",       // ADD  $0x80, %rsp
          is_indirect_call ? 37 : 47
#elif defined(__i386__)
          "\x68\x00\x00\x00\x00"            // PUSH . + 11
          "\x68\x00\x00\x00\x00"            // PUSH return_addr
          "\x68\x00\x00\x00\x00"            // PUSH $syscall_enter_with_frame
          "\xC3",                           // RET
          16
#else
#error Unsupported target platform
#endif
          );


      memcpy(dest + preamble +
#if defined(__x86_64__)
          (is_indirect_call ? 37 : 47),
#elif defined(__i386__)
          16,
#else
  #error Unsupported target platform
#endif
       code[i].addr + code[i].len, postamble);

      DPRINT(DEBUG_ALL, "I used %d\n", preamble + postamble + 47); 

    // note is_indirect_call always false  
#if defined(__x86_64__)
      int post = preamble + (is_indirect_call ? 37 : 47) + postamble;
      dest[post] = '\xE9'; // JMPQ

      // address to go back 
      // if postamble is 0 second points to i 
      *(int *)(dest + post + 1) =
        (code[second].addr + code[second].len) - (dest + post + 5);

      DPRINT(DEBUG_ALL, "Next instruction address is %p the callback address %d\n", code[second].addr + code[second].len ,*(dest + post +1)); 

      if (is_indirect_call) {
//        *(int *)(dest + preamble + 13) = vsys_offset;
        //TODO insert support to vsyscall 
        irreversible_error("Vsyscall no supported yet"); 
      
      } else {
        *(int *)(dest + preamble + 11) =
          (code[second].addr + code[second].len) - (dest + preamble + 15);
        *(void **)(dest + preamble + 18) =
          (void *)(&syscall_enter_with_frame);
      }
#elif defined(__i386__)
      *(dest + preamble + 16 + postamble) = '\x68'; // PUSH
      *(char **)(dest + preamble + 17 + postamble) = code[second].addr + code[second].len;
      *(dest + preamble + 21 + postamble) = '\xC3'; // RET
      *(char **)(dest + preamble + 1) = dest + preamble + 16;
      *(char **)(dest + preamble + 6) = code[second].addr + code[second].len;
      *(void (**)())(dest + preamble + 11) = syscall_enter_with_frame;
#else
      #error Unsupported target platform
#endif
//      pad unused space in the original function with nops
     
      
      // I need to make it writable
      //
      
      char *page_address = GET_PAGE_ADDRESS(code[first].addr); 
     
      DPRINT(DEBUG_ALL, "Original address %p, Page address %p \n", code[first].addr, page_address);  

      make_writable(page_address, true); 
      
      memset( code[first].addr,0x90 , code[second].addr + code[second].len - code[first].addr);
      
      // Replace the system call with an unconditional jump to our new code.
#if defined(__x86_64__)
      *code[first].addr = '\xe9';   // jmpq
      *(int *)(code[first].addr + 1) = dest - (code[first].addr + 5);
       DPRINT(DEBUG_INFO, "Jump address 0x%lx\n", (uintptr_t)dest - ((uintptr_t)code[first].addr + 5) );  
#elif defined(__i386__)
      code[first].addr[0] = '\x68'; // push
      *(char **)(code[first].addr + 1) = dest;
      code[first].addr[5] = '\xc3'; // ret
#else
#error unsupported target platform
#endif
   
     make_writable(page_address, false); 
    
    }  //this close the if  
replaced:
    i = (i + 1) % (sizeof(code) / sizeof(struct code));
  } /* this close the cycle */ 
}


