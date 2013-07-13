#include <stdio.h> 

#include "../error.h"
#include "../common.h" 
#include "../maps.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



int main(int argc, const char *argv[])
{
  struct maps maps;
  int self_maps = open("/proc/self/maps", O_RDONLY, 0);

  if (self_maps < 0) 
    die("Cannot access \"/proc/self/maps\"");

  maps_init(&maps, self_maps);
  maps_read(&maps);

  return 0;
}
