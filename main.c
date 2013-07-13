#include "tracer.h"
#include "common.h"
#include "sandbox.h" 
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h>
#include <signal.h>
#include <stdbool.h> 
#include <sys/types.h>
#include <string.h> 
#include <getopt.h> 
//run child process 

void run_preocess(char * const argv[], const char * ip, 
                  const char * port, const char * visibility ) 
{
    // set the IP of the server
    if (ip)
        setenv(MVH_SERVER_IP, ip, OVERWRITE); 
   // set the server port 
    if (port)
        setenv(MVH_SERVER_PORT, port, OVERWRITE); 
    //set the visibility of the process 
    if (visibility) 
        setenv(MVH_PROCESS_VISIBILITY, visibility, OVERWRITE); 
    // load the shared object within the new process enviroment 
    if (putenv("LD_PRELOAD=./preload.so") < 0)
        die("Failed putenv (LD_PRELOAD)"); 
    // execute the application
    if (execv(argv[0], argv) < 0)
        die("Failed execv");
}

/*
 * Verify the binary file has the verify dynamic symbol 
 * __lib_start_main
 */ 
void verify_dynamic_symbol( const char * application){

  char command[SIZE_COMMAND]={0}; 
  FILE * fp=NULL; 
  int nread=0; 

  snprintf(command, sizeof(command),
             "objdump -T %s | grep __libc_start_main", application);
  fp = popen((const char *)command, "r");
 
  DPRINT(DEBUG_INFO, "Running : %s\n", command); 
  
  memset(command, 0, SIZE_COMMAND); 
  
  INTR_RES(fread(command, 1, SIZE_COMMAND, fp), nread); 

  pclose(fp); 

  if(strstr(command, "__libc_start_main") == NULL || nread == 0) 
      irreversible_error("Symbol __libc_start_main not found"); 
   
  DPRINT(DEBUG_INFO, "Result retrivied from objdump : %s", command); 
  
  return; 
}

int main(int argc,  char * const argv[]){

    int opt=-1;
    int optarg_len; 
    int len=0; 
    
    char * ip= NULL,  * port = NULL, * visibility= NULL;  

    static struct option long_options[] = {
                   {"public",  no_argument, 0,  1 },
                   {"private", no_argument, 0,  2 },
                   {0,         0,           0,  0 }
                   }; 
   
    if ( argc <= 2)
       argument_error(argv[0], usage); 

   while ((opt = getopt_long(argc, argv, "+p:s:", long_options, NULL)) != EOF) {
     switch (opt) {
        case 's': /*server ip*/
            ip=optarg; 
            DPRINT(DEBUG_INFO, "Set server ip to %s\n", ip); 
            break;
        case 'p': /*server port */
            port=optarg;
            DPRINT(DEBUG_INFO, "Set server port to %s\n", port); 
            break;
        case 1:  /* Public process */
            visibility = "public";  
            DPRINT(DEBUG_INFO, "This process has been configured as %s\n",
                   visibility); 
            break; 
        case 2: /* Private process */
            visibility = "private";  
            DPRINT(DEBUG_INFO, "This process has been configured as %s\n",
                   visibility); 
            break; 
        default: /* '?' */
            argument_error(argv[0],usage);
        }
    }

    if(visibility == NULL){
      fprintf(stderr, "You must specify the process visibility\n"); 
      argument_error(argv[0], usage); 
    }

    argv += optind; 
    // install the sanbox enviroment 
    verify_dynamic_symbol(argv[0]);
    // run the untrusted application
    run_preocess(argv, ip, port, visibility);  
    
    return 0;
}
