
all : raw_clone clone  malloc brk thread 

malloc : malloc.c 
	gcc malloc.c -o malloc.out 

brk : brk.c 
	gcc brk.c -o brk.out 

thread : thread.c 
	gcc thread.c -lpthread -o thread.out

clone : clone.c 
	gcc clone.c -o clone.out

raw_clone : raw_clone.c 
	gcc -g raw_clone.c -o raw_clone.out


clean: 
	rm *.out
