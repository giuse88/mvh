#include "tls.h"
#include <asm/ldt.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <asm/prctl.h>

void * install_tls() {
  void *addr = mmap(0, 4096, PROT_READ|PROT_WRITE,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (arch_prctl(ARCH_SET_GS, addr) < 0) 
      return NULL;
    
   return addr;
}

void freeTLS() {
    void *addr;
    arch_prctl(ARCH_GET_GS, &addr);
    munmap(addr, 4096);
}

bool set_tls_value(int idx, unsigned long val) {
    if (idx < 0 || idx >= 4096/8) {
      return false;
    }
    asm volatile(
        "movq %0, %%gs:(%1)\n"
        :
        : "q"((void *)val), "q"(8ll * idx));
    return true;
}


unsigned long get_tls_value(int idx) {
    long long rc;
    if (idx < 0 || idx >= 4096/8) {
      return 0;
    }
    asm volatile(
        "movq %%gs:(%1), %0\n"
        : "=q"(rc)
        : "q"(8ll * idx));
    return rc;
  }
