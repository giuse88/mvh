#include <stdio.h>
#include <unistd.h> 
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, const char *argv[])
{
 
  char * buf =NULL; 
  int j=0, i;
  int fd=0; 


  if ( (fd=open("/usr/lib64/locale/locale-archive", O_RDONLY)) < 0 )
      perror("OPEN");

 if (!(buf= mmap(NULL, 1607632, PROT_READ, MAP_PRIVATE, fd, 0)))
      perror("MMAP"); 
 else 
      puts("MAPS okay"); 


   close(fd); 

  for ( i =0; i< 1607632; i++)
    j= buf[i]; 

 puts("Memory verified for local_archive"); 

  if ( (fd=open("/usr/local/lib/mod_indexfile.so", O_RDONLY)) < 0) 
      perror("Open"); 

  if ((buf=mmap(NULL, 2105520, PROT_READ , MAP_PRIVATE, fd, 0)))
        puts("Map okay");
  else 
      perror("MMAP"); 

    close(fd); 
 
 for (i =0; i< 2105520; i++)
    printf("%d  : %d\n", i, buf[i]);  

 puts("Memory verified for mod_indexfile.so"); 
    return 0;
}
