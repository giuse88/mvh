#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "hacking.h"

#define PORT                 80  
#define WEBROOT              "/var/www/localhost/htdocs/"  
#define REQUEST              1000
#define SIZE_BUFFER          1000  


int recv_line(int sockfd, unsigned char *dest_buffer); 
int send_string(int sockfd, unsigned char *buffer); 
void handle_connection(int, struct sockaddr_in *); 
int get_file_size(int); 



int main(void) {
   int sockfd, new_sockfd, yes=1; 
   struct sockaddr_in host_addr, client_addr;   // my address information
   socklen_t sin_size;


   printf("Accepting web requests on port %d\n", PORT);

   if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
      fatal("in socket");

   if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
      fatal("setting socket option SO_REUSEADDR");

   host_addr.sin_family = AF_INET;      // host byte order
   host_addr.sin_port = htons(PORT);    // short, network byte order
   host_addr.sin_addr.s_addr = INADDR_ANY; // automatically fill with my IP
   memset(&(host_addr.sin_zero), '\0', 8); // zero the rest of the struct

   if (bind(sockfd, (struct sockaddr *)&host_addr, sizeof(struct sockaddr)) == -1)
      fatal("binding to socket");

   if (listen(sockfd, 20) == -1)
      fatal("listening on socket");

   while(1) {   // Accept loop
      sin_size = sizeof(struct sockaddr_in);
      new_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size);
      if(new_sockfd == -1)
         fatal("accepting connection");

      handle_connection(new_sockfd, &client_addr);
   }
   return 0;
}

/* This function handles the connection on the passed socket from the
 * passed client address.  The connection is processed as a web request
 * and this function replies over the connected socket.  Finally, the 
 * passed socket is closed at the end of the function.
 */
void handle_connection(int sockfd, struct sockaddr_in *client_addr_ptr) {
   unsigned char *ptr, request[REQUEST], resource[REQUEST];
   int fd, length;

   memset(request, 0,  REQUEST); 
   memset(resource, 0,  REQUEST); 
   length = recv_line(sockfd, request);

   printf("Got request from %s:%d lenght: %d  \n", inet_ntoa(client_addr_ptr->sin_addr), ntohs(client_addr_ptr->sin_port),length);
   puts("--------------------------------\n"); 
   printf("%.*s", 500, request);
   puts("--------------------------------"); 
   
   
   ptr = strstr(request, " HTTP/"); // search for valid looking request
   if(ptr == NULL) { // then this isn't valid HTTP
      printf(" NOT HTTP!\n");
   } else {
      *ptr = 0; // terminate the buffer at the end of the URL
      ptr = NULL; // set ptr to NULL (used to flag for an invalid request)
      if(strncmp(request, "GET ", 4) == 0)  // get request
         ptr = request+4; // ptr is the URL
      if(strncmp(request, "HEAD ", 5) == 0) // head request
         ptr = request+5; // ptr is the URL

      if(ptr == NULL) { // then this is not a recognized request
         printf("\tUNKNOWN REQUEST!\n");
      } else { // valid request, with ptr pointing to the resource name
         if (ptr[strlen(ptr) - 1] == '/')  // for resources ending with '/'
            strcat(ptr, "index.html");     // add 'index.html' to the end
         strcpy(resource, WEBROOT);     // begin resource with web root path
         strcat(resource, ptr);         //  and join it with resource path
         fd = open(resource, O_RDONLY, 0); // try to open the file
         printf("Opening \'%s\'\t", resource);
         if(fd == -1) { // if file is not found
            printf(" 404 Not Found\n");
            send_string(sockfd, "HTTP/1.0 404 NOT FOUND\r\n");
            send_string(sockfd, "Server: Tiny webserver\r\n\r\n");
            send_string(sockfd, "<html><head><title>404 Not Found</title></head>");
            send_string(sockfd, "<body><h1>URL not found</h1></body></html>\r\n");
         } else {      // otherwise, serve up the file
            printf(" 200 OK\n\n");
            send_string(sockfd, "HTTP/1.0 200 OK\r\n");
            send_string(sockfd, "Server: Tiny webserver\r\n\r\n");
            if(ptr == request + 4) { // then this is a GET request
               if( (length = get_file_size(fd)) == -1)
                  fatal("getting resource file size");
               if( (ptr = (unsigned char *) malloc(length)) == NULL)
                  fatal("allocating memory for reading resource");
               read(fd, ptr, length); // read the file into memory
               write(sockfd, ptr, length);  // send it to socket
               free(ptr); // free file memory
            }
            close(fd); // close the file
         } // end if block for file found/not found
      } // end if block for valid request
   } // end if block for valid HTTP
   shutdown(sockfd, SHUT_RDWR); // close the socket gracefully
   return; 
}

/* This function accepts an open file descriptor and returns     
 * the size of the associated file.  Returns -1 on failure.
 */
int get_file_size(int fd) {
   struct stat stat_struct;

   if(fstat(fd, &stat_struct) == -1)
      return -1;
   return (int) stat_struct.st_size;
}

/* This function accepts a socket FD and a ptr to the null terminated
 * string to send.  The function will make sure all the bytes of the
 * string are sent.  Returns 1 on success and 0 on failure.
 */
int send_string(int sockfd, unsigned char *buffer) {
   int sent_bytes, bytes_to_send;
   bytes_to_send = strlen(buffer); 
   while(bytes_to_send > 0) {
      sent_bytes = write(sockfd, buffer, bytes_to_send);
      if(sent_bytes == -1)
         return 0; // return 0 on send error
      bytes_to_send -= sent_bytes;
      buffer += sent_bytes;
   }
   return 1; // return 1 on success
}

/* This function accepts a socket FD and a ptr to a destination
 * buffer.  It will receive from the socket until the EOL byte
 * sequence in seen.  The EOL bytes are read from the socket, but
 * the destination buffer is terminated before these bytes.
 * Returns the size of the read line (without EOL bytes).
 */
int recv_line(int sockfd, unsigned char *dest_buffer) {
   unsigned char temp_buf[SIZE_BUFFER], *ptr, *ptr_dest_buffer;
   int eol_matched = 0;
   int i=0; 
   ssize_t n_read; 

   ptr = dest_buffer;
  
   memset(temp_buf, 0, SIZE_BUFFER); 
   n_read= read(sockfd, temp_buf, SIZE_BUFFER); 

   for (i=0; i < n_read && i < SIZE_BUFFER; i++, ptr++)
     *ptr=temp_buf[i]; 

   return i;  //didn't find the end of line characters
}
