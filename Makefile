CC=gcc 
FLAGS=-g  -std=gnu99 -O0  
DEBUG= -DCOLOR -DDEBUG 
LDFLAGS=-ldl -g -lpthread  
PWD=`pwd`
LIB=
LINKER=gcc

all : mvh build_server 

build_server: main_mvh_server.c mvh_server.c error.c
	${CC} -g  ${DEBUG}  ${FLAGS} -lpthread main_mvh_server.c server_handler.c mvh_server.c error.c -o mvh_server 

mvh : main.o mvh.o error.o preload.so  
	${LINKER} main.o mvh.o error.o -o mvh 	

mvh.o: mvh.c 
	${CC} mvh.c  -c ${DEBUG}  ${FLAGS} -o mvh.o

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

handler.o: handler.c
	${CC} handler.c -fPIC -c ${FLAGS} ${DEBUG} -o handler.o

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

preload.so: tls.o handler.o syscall_table.o fault.o mmalloc.o library.o maps.o sandbox.o preload.o error.o trusted_thread.o bpf-filter.o x86_decoder.o syscall_entrypoint.o 
	${LINKER} ${LDFLAGS} -fPIC -shared handler.o error.o tls.o  fault.o syscall_table.o x86_decoder.o library.o bpf-filter.o maps.o mmalloc.o  preload.o syscall_entrypoint.o sandbox.o trusted_thread.o -o preload.so 

run: mvh preload.so  
	@ ./mvh --private -s 127.0.0.1 -p 5555  /bin/ls -a 
#	@ ./mvh toys/function_address.out  

ls: mvh preload.so toys 
	@ ./mvh /bin/ls   

toys:  function_address.out 

function_address.out: toys/function_address.c 
	${CC} toys/function_address.c -o toys/function_address.out 

read_maps.out : toys/read_maps.c 
	${CC} toys/read_maps.c -c ${FLAGS} ${DEBUG} -o toys/read_maps.o 
	${LINKER} -g toys/read_maps.o mmalloc.o error.o library.o maps.o x86_decoder.o -o toys/read_maps.out

thread:  
	@ ./mvh --public ./toys/thread.out  

clone: 
	@ ./mvh --public ./toys/clone.out  

server: build_server 
	@ ./mvh_server   

public:  
	@ ./mvh --public /bin/ls   
private:  
	@ ./mvh --private /bin/ls   

gdb: mvh preload.so 
	@ gdb ./mvh 
strace: 
	@ strace -ff ./mvh /bin/ls -o calls.txt 
clean: 
	rm *.o *.so mvh mvh_server  
