#include "mvh.h"
#include "common.h" 
#include <stdlib.h> 
#include <unistd.h> 

#define SIZE_COMMAND 256

const char * version= VERSION; 
const char * usage = USAGE; 


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


