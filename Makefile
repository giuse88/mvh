CC=gcc 
FLAGS=-g  -std=gnu99 -O0  
DEBUG=  #-DDEBUG 
LDFLAGS=-ldl -g -lpthread  
PWD=`pwd`
LIB=
LINKER=gcc

all : tracer.out 

tracer.out : main.o error.o preload.so  
	${LINKER} main.o error.o -o tracer.out 	

main.o : main.c 
	${CC} main.c  -c ${DEBUG}  ${FLAGS} -o main.o

tls.o: tls.c 
	${CC} tls.c -fPIC -c ${DEBUG} ${FLAGS} -o tls.o 

error.o: error.c 
	${CC} error.c -fPIC -c ${DEBUG} ${FLAGS} -o error.o 

sandbox.o: sandbox.c
	${CC} sandbox.c -fPIC -c ${DEBUG} ${FLAGS} -o sandbox.o 

trusted_thread.o: trusted_thread.c
	${CC} trusted_thread.c -fPIC -c ${DEBUG} ${FLAGS} -o trusted_thread.o 

maps.o: maps.c
	${CC} maps.c -fPIC -c ${FLAGS} ${DEBUG} -o maps.o

bpf-filter.o: bpf-filter.c
	${CC} bpf-filter.c -fPIC -c ${FLAGS} ${DEBUG} -o bpf-filter.o

library.o: library.c
	${CC} library.c -fPIC -c ${FLAGS} ${DEBUG} -o library.o

mmalloc.o: mmalloc.c
	${CC} mmalloc.c -fPIC -c ${FLAGS} ${DEBUG} -o mmalloc.o

x86_decoder.o: x86_decoder.c
	${CC} x86_decoder.c -fPIC -c ${FLAGS} ${DEBUG} -o x86_decoder.o

fault.o: fault.S
	${CC} fault.S -fPIC -c ${FLAGS} ${DEBUG} -o fault.o

syscall_entrypoint.o: syscall_entrypoint.c
	${CC} syscall_entrypoint.c -fPIC -c ${FLAGS} ${DEBUG} -o syscall_entrypoint.o

syscall_table.o: syscall_table.c
	${CC} syscall_table.c -fPIC -c ${FLAGS} ${DEBUG} -o syscall_table.o

preload.o: preload.c
	${CC} preload.c -fPIC -c ${FLAGS} ${DEBUG} -o preload.o

preload.so: tls.o  syscall_table.o fault.o mmalloc.o library.o maps.o sandbox.o preload.o error.o trusted_thread.o bpf-filter.o x86_decoder.o syscall_entrypoint.o 
	${LINKER} ${LDFLAGS} -fPIC -shared error.o tls.o  fault.o syscall_table.o x86_decoder.o library.o bpf-filter.o maps.o mmalloc.o  preload.o syscall_entrypoint.o sandbox.o trusted_thread.o -o preload.so 

run: tracer.out preload.so  
	@ ./tracer.out --private /bin/ls   
#	@ ./tracer.out toys/function_address.out  

ls: tracer.out preload.so toys 
	@ ./tracer.out /bin/ls   

toys:  function_address.out 

function_address.out: toys/function_address.c 
	${CC} toys/function_address.c -o toys/function_address.out 

read_maps.out : toys/read_maps.c 
	${CC} toys/read_maps.c -c ${FLAGS} ${DEBUG} -o toys/read_maps.o 
	${LINKER} -g toys/read_maps.o mmalloc.o error.o library.o maps.o x86_decoder.o -o toys/read_maps.out

thread: 
	@ ./tracer.out ./toys/thread.out  

clone: 
	@ ./tracer.out ./toys/clone.out  

gdb: tracer.out preload.so 
	@ gdb ./tracer.out 
strace: 
	@ strace -ff ./tracer.out /bin/ls -o calls.txt 
clean: 
	rm *.o *.out *.so 
