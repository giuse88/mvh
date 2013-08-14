#include "sandbox.h"
#include "trusted_thread.h"
#include "syscall_table.h"
#include "maps.h"
#include "common.h"
#include "tls.h" 
#include <dirent.h> 
#include <unistd.h>
#include <signal.h> 
#include <sys/types.h>          
#include <string.h> 
#include <stdlib.h> 
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define __USE_GNU     1
#define _GNU_SOURCE   1

struct sandbox_info sandbox; 
struct sigaction sa_segv_;

void segv_sig_handler(int signo, siginfo_t *context, void *unused)
    asm("segv_sig_handler") INTERNAL;


void alert(int signo, siginfo_t *context, void *unused){
DPRINT(DEBUG_INFO, "****************************************** SIGNAL ********************************************\n"); 
}

void install_sandbox_configuration(){

    char * ip= NULL,  * port = NULL, * visibility= NULL;  
   
    memset(&sandbox, 0, sizeof(struct sandbox_info)); 
    
    if ((ip=getenv(MVH_SERVER_IP)))
    {   /* Set the IP of the server from the enviroment variable*/ 
        int ip_length=strlen(ip)+1;
        int len = (ip_length>= MAX_IP_LENGTH) ? MAX_IP_LENGTH : ip_length; 
        strncpy(sandbox.connection.ip, ip, len); 
    }
    else 
      strncpy(sandbox.connection.ip, DEFAULT_IP, sizeof(DEFAULT_IP)); 
    
    // get server port
    if ((port=getenv(MVH_SERVER_PORT)))
      sandbox.connection.port = atoi(port); 
    else  
      sandbox.connection.port = DEFAULT_PORT; 
   
    DPRINT(DEBUG_INFO, "Remote process is at IP %s:%d\n",sandbox.connection.ip,
                                                        sandbox.connection.port);
    
    // get server visibility
    if (!(visibility=getenv(MVH_PROCESS_VISIBILITY)))
       die("Process visibility has not been set corectelly"); 
    
    if (!strncmp(visibility, PUBLIC_STRING, sizeof(PUBLIC_STRING)))
        sandbox.visibility = PUBLIC; 
    else if (!strncmp(visibility, PRIVATE_STRING, sizeof(PRIVATE_STRING)))
        sandbox.visibility = PRIVATE; 
    else 
        die("Imposible to recognize the visibility of the process"); 

    sandbox.process = getpid(); 
    sandbox.status = DISABLE; 
}
void setup_signal_handlers() {
  // Set SIGCHLD to SIG_DFL so that waitpid() can work
  struct sigaction sa;
  sigset_t mask;
  
  memset(&mask, 0x00, sizeof(mask));
  memset(&sa, 0, sizeof(sa));
 
  sigemptyset(&mask);
	sigaddset(&mask, SIGSYS);
	sigaddset(&mask, SIGCHLD);
  sigaddset(&mask, SIGSEGV);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGPIPE);
  sigaddset(&mask, SIGUSR1);
  sigaddset(&mask, SIGUSR2);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGHUP);
  sigaddset(&mask, SIGALRM);
 
  sa.sa_handler = SIG_DFL;
  sigaction(SIGCHLD, &sa, NULL);
  
  // Set up SEGV handler for dealing with RDTSC instructions, system calls
  // that have been rewritten to use INT0, for sigprocmask() emulation, for
  // the creation of threads, and for user-provided SEGV handlers.
  sa.sa_sigaction = segv_sig_handler;
  sa.sa_flags = SA_SIGINFO ;
  sigaction(SIGSEGV, &sa, &sa_segv_);

  // Set up SYS handler for dealing with BPF trap. 
  sa.sa_sigaction =  emulator;
  sa.sa_flags      = SA_SIGINFO;
  sigaction(SIGSYS, &sa, NULL);

  // Set up SYS handler for dealing with BPF trap. 
  sa.sa_sigaction =  alert;
  sa.sa_flags      = SA_SIGINFO;
  sigaction(SIGHUP, &sa, NULL);
  
  // Set up SYS handler for dealing with BPF trap. 
  sa.sa_sigaction =  alert;
  sa.sa_flags      = SA_SIGINFO;
  sigaction(SIGPIPE, &sa, NULL);
 
  // Set up SYS handler for dealing with BPF trap. 
  sa.sa_sigaction =  alert;
  sa.sa_flags      = SA_SIGINFO;
  sigaction(SIGINT, &sa, NULL);
 
  // Set up SYS handler for dealing with BPF trap. 
  sa.sa_sigaction =  alert;
  sa.sa_flags      = SA_SIGINFO;
  sigaction(SIGUSR1, &sa, NULL);
  
  // Set up SYS handler for dealing with BPF trap. 
  sa.sa_sigaction =  alert;
  sa.sa_flags      = SA_SIGINFO;
  sigaction(SIGUSR2, &sa, NULL);
  
  // Set up SYS handler for dealing with BPF trap. 
  sa.sa_sigaction =  alert;
  sa.sa_flags      = SA_SIGINFO;
  sigaction(SIGTERM, &sa, NULL);

  // Set up SYS handler for dealing with BPF trap. 
  sa.sa_sigaction =  alert;
  sa.sa_flags      = SA_SIGINFO;
  sigaction(SIGALRM, &sa, NULL);


	if (sigprocmask(SIG_UNBLOCK, &mask, NULL))
      die("Sigprocmask"); 
}

void close_file_descriptors() {

    // Close all file handles except for sandboxFd, cloneFd, and stdio
    DIR *dir                   = opendir("/proc/self/fd");
    if (dir == 0) {
      // If we don't know the list of our open file handles, just try closing
      // all valid ones0l
      // _SC_OPEN_MAX contains the maximum number of file descriptors that 
      //  this process can open
      for (int fd = sysconf(_SC_OPEN_MAX); --fd > 2; ) 
          close(fd);
    } else {
      // If available, if is much more efficient to just close the file
      // handles that show up in /proc/self/fd/
      struct dirent de, *res;
      while (!readdir_r(dir, &de, &res) && res) {
        if (res->d_name[0] < '0')
          continue;
        int fd                 = atoi(res->d_name);
        if (fd > 2 &&
           fd != dirfd(dir)) {
          close(fd);
        }
      }
      closedir(dir);
    }

}

int start_sandbox() {
    
    install_sandbox_configuration(); 

    DPRINT(DEBUG_INFO, "Start the sandbox enviroment of the %s process\n", 
            sandbox.visibility==PUBLIC ? PUBLIC_STRING : PRIVATE_STRING ); 
    
    setup_signal_handlers(); 
    DPRINT(DEBUG_INFO, "Signal handler installed\n"); 
    
    /* Initialize the sytem call table containing the 
     * handler for each function */ 
    initialize_syscall_table(); 
    DPRINT(DEBUG_INFO, "System call table initialized \n"); 

    /*TODO Rewrite VSDO and vsyscall */ 

    // close all file descriptors open so far
    close_file_descriptors(); 

    // This may be moved to another position, only the trusted 
    // process uses it. 
    /*Get the file descriptor of the mapins */
    sandbox.self_maps = open("/proc/self/maps", O_RDONLY, 0);
    if (sandbox.self_maps < 0) 
      die("Cannot access \"/proc/self/maps\"");

    /* Create the trusted thread and enter seccomp mode */ 
    if (create_trusted_thread() < 0 )
        die("Create trusted thread");

    sandbox.status = ENABLE;
    DPRINT(DEBUG_INFO, "Ends Sandbox\n");

    return 0; 
}
