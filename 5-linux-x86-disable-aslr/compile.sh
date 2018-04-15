#!/bin/bash

echo '[+] Assembling with Nasm ... '
nasm -f elf32 -o $1.o $1.nasm

echo '[+] Linking ...'
ld -o $1 $1.o -z execstack -m elf_i386

shellcode_c=$(objdump -d $1.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g')

echo '[+] Creating C wrapper...'
cat >shellcode-wrapper-$1.c << EOD
	#include<stdio.h>
	#include<string.h>
	unsigned char code[] = $shellcode_c;
	int main() {
		printf("Shellcode length: %d\n", strlen(code));
		int (*ret)() = (int(*)()) code;
		ret();
	}
EOD

echo '[+] Compiling C wrapper...'
gcc -ggdb -o shellcode-wrapper-$1 shellcode-wrapper-$1.c -fno-stack-protector -z execstack -m32

echo "[+] Done! Here is your shellcode ($(( ($(echo $shellcode_c | wc -c) - 2) / 4 )) bytes):"
echo $shellcode_c
