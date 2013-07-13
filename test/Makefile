all: no_main  

no_main: no_main.S
	  gcc -Wall -Wextra -nostdlib -Wl,-e_start no_main.S -o no_main.out


clean: 
	rm *.o *.out 
