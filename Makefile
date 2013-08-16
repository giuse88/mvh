CC=gcc 
CFLAGS = -g -std=gnu99 -O0 -Wall -Wextra -Wno-missing-field-initializers  \
				 -Wno-unused-parameter -I. -fno-stack-protector -z execstack 
DEBUG= -DCOLOR -DDEBUG 
LDFLAGS=-ldl -g -lpthread  
PWD=`pwd`
LIB=
LINKER=gcc

all : mvh build_server 

build_server: main_mvh_server.c mvh_server.c error.c
	${CC} -g  ${DEBUG}  ${CFLAGS} -lpthread utils.c main_mvh_server.c server_handler.c mvh_server.c error.c -o mvh_server 

mvh : main.o mvh.o error.o preload.so  
	${LINKER}  main.o mvh.o error.o -o mvh 	-fno-stack-protector -z execstack 

mvh.o: mvh.c 
	${CC} mvh.c  -c ${DEBUG}  ${CFLAGS} -o mvh.o

utils.o: utils.c 
	${CC} utils.c -fpic  -c ${DEBUG}  ${CFLAGS} -o utils.o


main.o : main.c 
	${CC} main.c  -c ${DEBUG}  ${CFLAGS} -o main.o

tls.o: tls.c 
	${CC} tls.c -fPIC -c ${DEBUG} ${CFLAGS} -o tls.o 

error.o: error.c 
	${CC} error.c -fPIC -c ${DEBUG} ${CFLAGS} -o error.o 

sandbox.o: sandbox.c
	${CC} sandbox.c -fPIC -c ${DEBUG} ${CFLAGS} -o sandbox.o 

trusted_thread.o: trusted_thread.c
	${CC} trusted_thread.c -fPIC -c ${DEBUG} ${CFLAGS} -o trusted_thread.o 

handler.o: handler.c
	${CC} handler.c -fPIC -c ${CFLAGS} ${DEBUG} -o handler.o

maps.o: maps.c
	${CC} maps.c -fPIC -c ${CFLAGS} ${DEBUG} -o maps.o


bpf-filter.o: bpf-filter.c
	${CC} bpf-filter.c -fPIC -c ${CFLAGS} ${DEBUG} -o bpf-filter.o

library.o: library.c
	${CC} library.c -fPIC -c ${CFLAGS} ${DEBUG} -o library.o

mmalloc.o: mmalloc.c
	${CC} mmalloc.c -fPIC -c ${CFLAGS} ${DEBUG} -o mmalloc.o

x86_decoder.o: x86_decoder.c
	${CC} x86_decoder.c -fPIC -c ${CFLAGS} ${DEBUG} -o x86_decoder.o

fault.o: fault.S
	${CC} fault.S -fPIC -c ${CFLAGS} ${DEBUG} -o fault.o

syscall_entrypoint.o: syscall_entrypoint.c
	${CC} syscall_entrypoint.c -fPIC -c ${CFLAGS} ${DEBUG} -o syscall_entrypoint.o

syscall_table.o: syscall_table.c
	${CC} syscall_table.c -fPIC -c ${CFLAGS} ${DEBUG} -o syscall_table.o

preload.o: preload.c
	${CC} preload.c -fPIC -c ${CFLAGS} ${DEBUG} -o preload.o

preload.so: tls.o utils.o  handler.o syscall_table.o fault.o mmalloc.o library.o maps.o sandbox.o preload.o error.o trusted_thread.o bpf-filter.o x86_decoder.o syscall_entrypoint.o 
	${LINKER}  ${LDFLAGS} -fPIC -shared handler.o utils.o error.o tls.o  fault.o syscall_table.o x86_decoder.o library.o bpf-filter.o maps.o mmalloc.o  preload.o syscall_entrypoint.o sandbox.o trusted_thread.o -o preload.so 

hope: tls.c utils.c  handler.c syscall_table.c fault.S  mmalloc.c library.c maps.c sandbox.c preload.c  error.c trusted_thread.c bpf-filter.c x86_decoder.c syscall_entrypoint.c 
	${LINKER} -std=gnu99 -g -fno-stack-protector -z execstack ${DEBUG} ${LDFLAGS}  handler.c utils.c error.c tls.c  fault.S syscall_table.c x86_decoder.c maps.c  library.c bpf-filter.c mmalloc.c  syscall_entrypoint.c sandbox.c trusted_thread.c tinyweb.c   -o hope



private-http: 	
	./mvh --private /home/giuseppe/lighttpd-1.4.28/src/lighttpd -D -f /home/giuseppe/lighttpd-1.4.28/lighttpd.conf 

public-http: 	
	./mvh --public /home/giuseppe/lighttpd-1.4.28/src/lighttpd -D -f /home/giuseppe/lighttpd-1.4.28/lighttpd_2.conf 

run: mvh preload.so  
	@ ./mvh --private -s 127.0.0.1 -p 5555  /bin/ls -a 
#	@ ./mvh toys/function_address.out  

ls: mvh preload.so toys 
	@ ./mvh /bin/ls   

toys:  function_address.out 

function_address.out: toys/function_address.c 
	${CC} toys/function_address.c -o toys/function_address.out 

read_maps.out : toys/read_maps.c 
	${CC} toys/read_maps.c -c ${CFLAGS} ${DEBUG} -o toys/read_maps.o 
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
	rm *.o *.so mvh mvh_server  hope
