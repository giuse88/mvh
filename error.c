#include "error.h"  

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void  die (const char * str) {
    perror(str); 
    exit(EXIT_FAILURE);
}

/** 
 * program_name: the name of the program
 * usage the correct usage of the application 
 **/ 

void  argument_error(const char * program_name, const char * usage) {
    fprintf(stderr, "%s : no input file \n", program_name); 
    fprintf(stderr, "%s\n", usage); 
    exit(EXIT_FAILURE); 
}

void irreversible_error(const char * error_str) {
  
  fprintf(stderr, "::IRREVERSIBLE ERROR:: %s:%d %s\n", __FILE__, __LINE__, error_str); 
  exit(EXIT_FAILURE); 
}
