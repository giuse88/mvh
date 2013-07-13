#ifndef MVH_H
#define MVH_H

#define VERSION  "0.1" 
#define USAGE    "usage:\n mvh [-s ip] [-p port] [:private:public] PROG [ARGS]" 

extern const char * usage; 
extern const char * version; 

extern void run_preocess(char * const argv[], const char * , 
                  const char * , const char *); 
extern void verify_dynamic_symbol(const char *);  

#endif /* end of include guard: MVH_H */
