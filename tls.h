#ifndef TLS_H
#define TLS_H

#include <stdbool.h>

void *install_tls(); 
void freeTLS();
bool set_tls_value (int, unsigned long); 
unsigned long get_tls_value(int ); 

/*
 *macros used to set and retrieve the values 
 from the tls area
*/ 

#define TLS_TID 0x0
#define TLS_FD  0x8 
#define TLS_MONITORED 0x10

#define set_local_tid(_x) \
    set_tls_value(TLS_TID, (unsigned long)_x)

#define set_local_fd(_x) \
    set_tls_value(TLS_FD, (unsigned long)_x)

#define set_local_monitored(_x) \
    set_tls_value(TLS_MONITORED, (unsigned long)_x)

#define get_local_tid() \
    get_tls_value(TLS_TID)

#define get_local_fd() \
    get_tls_value(TLS_FD)

#define get_local_monitored() \
    get_tls_value(TLS_MONITORED)



#endif /* end of include guard: TLS_H */
