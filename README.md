MVH
===

#Multi Variant Honeypot 

MVH stands for Multi Variant Honeypot. This is my MSc final project. MVH is a multi variant honeypot system which uses a interposition delegating architecture to execute untrusted code built with Seccomp-BPF. MVH has two variants, one private and one public running in parallel and it is able to detect, prevent and record malicious behaviour of the public variant (e.g. public web server) by analysing and comparing the system calls made by each variant. 
The MVH effectiveness has been proved by attacking a LightHTTP server affected by a buffer overflow bug. MVH was able to prevent and record any malicious action performed by the attacked.

#Interested?

