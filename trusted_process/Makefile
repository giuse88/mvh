OPT= #-DDEBUG 

all : server

run: server
	@ ./server.out

server: server.c 
	gcc ${OPT} -g -std=gnu99 -lpthread  ../error.c server.c -o server.out

clean: 
	rm *.out 
