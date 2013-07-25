#ifndef CONF_H
#define CONF_H

// Environment variables used by the main application 
// to communicate with the LD+Preload object 
#define MVH_SERVER_IP           "MVH_SERVER_IP"
#define MVH_SERVER_PORT         "MVH_SERVER_PORT"
#define MVH_PROCESS_VISIBILITY  "MVH_PROCESS_VISIBILITY"

// Default configuration options
#define DEFAULT_IP              "127.0.0.1" 
#define DEFAULT_PORT            5555
#define SERVER_TIMEOUT          3 * 60 * 1000
#define PUBLIC_STRING           "public" 
#define PRIVATE_STRING          "private" 
// nano seconds
#define TEMPORAL_WINDOW          500000000  
//#define   TEMPORAL_WINDOW         1
#define MAX_FD                   100 
#endif /* end of include guard: CONF_H */
