#include <elf.h>
#include <dlfcn.h> 
#include <link.h>

#include "debug.h" 
#include "error.h"
#include "sandbox.h"


typedef int (*main_t)(int, char **, char **);
main_t realmain;


int wrap_main(int argc, char **argv, char **environ)
{
  if (start_sandbox())
      die("Failed start delegating mechanism"); 
 
  DPRINT(DEBUG_INFO, " === LD_PRELOAD ends === \n\n");

  return (*realmain)(argc, argv, environ);
}


int __libc_start_main(main_t main,
                      int argc,
                      char *__unbounded *__unbounded ubp_av,
                      ElfW(auxv_t) *__unbounded auxvec,
                      __typeof (main) init,
                      void (*fini) (void),
                      void (*rtld_fini) (void), void *__unbounded
                      stack_end) {
  void *libc;
  int (*libc_start_main)(main_t main,
                         int,
                         char *__unbounded *__unbounded,
                         ElfW(auxv_t) *,
                         __typeof (main),
                         void (*fini) (void),
                         void (*rtld_fini) (void),
                         void *__unbounded stack_end);

  DPRINT(DEBUG_INFO, " === LD_PRELOAD begins === \n");

  libc = dlopen("libc.so.6", RTLD_LOCAL  | RTLD_LAZY);
  if (!libc) 
    die("dlopen() failed"); 
  
  libc_start_main = dlsym(libc, "__libc_start_main");
  
  if (!libc_start_main) 
      die("__libc_start_main not found"); 


  DPRINT(DEBUG_INFO, "libc_start_main at %lx \n", (uintptr_t) libc_start_main);

  realmain = main;

  return (*libc_start_main)(wrap_main, argc, ubp_av, auxvec, init, fini, rtld_fini, stack_end);
}

