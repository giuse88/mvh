OPT= -fno-stack-protector -z execstack -g  


all : exploit  shellcode  webserver

webserver : tinyweb.c tinyweb_vuln.c 
	gcc $(OPT) -o tinyweb tinyweb.c
	gcc $(OPT) -o tinyweb_vuln tinyweb_vuln.c


exploit : exploit.c mvh_exploit.c  
	gcc exploit.c -o exploit -g
	gcc mvh_exploit.c -o mvh_exploit -g

gdb: 
	 sudo gdb -q --pid=`pidof tinyweb_vuln` --symbols=./tinyweb_vuln

shellcode : 
	gcc $(OPT)  -o shellcode shellcode.c
	gcc $(OPT)  -o remote_shellcode remote_shellcode.c

clean: 
	rm -rf remote_shellcode shellcode tinyweb exploit 
