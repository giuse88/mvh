#ifndef ERROR_H

#define ERROR_H


#include <error.h> 
#include <errno.h> 

#define ERROR_FUNCTION -1
#define SUCCESS 0 
/**
 * Error function called when the argments 
 * of the function are incorrect
 u*/ 

void argument_error(const char * app_name, const char * usage) __attribute__((noreturn));  

/* 
 * Die called perror with the string specified 
 * as argument.
 */ 

void die( const char *) __attribute__((noreturn)); 

void irreversible_error(const char * error_str) __attribute__ ((noreturn)); 
#endif /* end of include guard: ERROR_H */
