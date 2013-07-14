#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h> 
#include "common.h" 
#include "conf.h" 
#include "mvh_server.h"
#include "color.h" 

const char * usage = "mvh_server [hp] \
                      -p server port  \
                      -h this help   "; 

int main(int argc, char *argv[])
{
  int opt =-1;
  int port=-1; 

  port=DEFAULT_PORT;

  while ((opt = getopt(argc, argv, "+p:h:")) != EOF) 
     switch (opt) {
       case 'p': /*server port */
            port=atoi(optarg);
            DPRINT(DEBUG_INFO, "Set server port to %d\n", port); 
            break;
       case 'h': 
            fprintf(stderr, "%s\n", usage);
            break; 
       default: /* '?' */
            argument_error(argv[0],usage);
        }

    run_mvh_server(port); 
}
