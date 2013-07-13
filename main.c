#include "mvh.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h>
#include <string.h> 
#include <getopt.h> 

int main(int argc,  char * const argv[]){

    int opt=-1;
    
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
