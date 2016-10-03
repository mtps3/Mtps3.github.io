---
layout: post
title: "TUM CTF 2016: zwiebel (rev 50)"
author: f0rki
categories: writeup
tags: [cat/reversing, tool/radare2, tool/angr]
---

* **Category:** rev
* **Points:** 50
* **Description:**

> I found this onion in my kitchen, may I ask you to dissect it?
> https://www.youtube.com/watch?v=LowwCyZHBBk

## Write-up

This was a pretty interesting reversing challenge, because I was able to
improve my radare2 automation skills :) But for 50 points I spent quite a while
on this challenge. So let's cut the zwiebel and remember you need sharp knives
otherwise you will probably start crying.

Let's start with the main function. It's pretty clear what is happening.

```
printf(str.Input_key);
fflush(obj.stdout)
char* input = &str.hxp_th15_15_c3rt41nly_n0t_th3_fl4g_;  // fake flag
fgets(input, obj.stdin, 0x90);
void* x = mmap(...);
memcpy(x, obj.shc, 0x24c8d);
x(input); // call x
```

So first thing was we tried to debug the `zwiebel`, but even before reaching
`main` it printed `:(` and exited. A quick check in radare revealed a
anti-debugging trick in `__printf`, which is called via the constructor.

```
[0x00400800]> afl~ptrace                     # check whether ptrace is imported
0x004006b0    2 16   -> 48   sym.imp.ptrace
[0x004006b0]> axt sym.imp.ptrace             # show xrefs to ptrace
call 0x4007db call sym.imp.ptrace in sym.__printf
[0x004006b0]> s sym.__printf
[0x004007d0]> axg                            # show xrefs graph to reach current function
- 0x00000000
  - 0x004008c9 fcn 0x00400880 sym.__libc_csu_init
  - 0x00400880 fcn 0x00400880 sym.__libc_csu_init
    - 0x004006e6 fcn 0x004006d0 entry0
```

This can easily be patched out by overwriting the call to `ptrace` or the
following `jne` or both with nops. Another way would be to preload a ptrace
implementation that always returns the right value. (e.g. using
[preeny](https://github.com/zardus/preeny)


Also there are a couple of fake flags in binary:

```
[0x004006d0]> izz~hxp
vaddr=0x00601280 paddr=0x00001280 ordinal=031 sz=36 len=35 section=.data type=ascii string=hxp{th15_15_c3rt41nly_n0t_th3_fl4g}
vaddr=0x006012a4 paddr=0x000012a4 ordinal=032 sz=30 len=29 section=.data type=ascii string=hxp{where_u_3quenTisTs_naoW?}
vaddr=0x006012c2 paddr=0x000012c2 ordinal=033 sz=28 len=27 section=.data type=ascii string=hxp{g0_st4rt_h4x0ring_pl0x}
vaddr=0x006012de paddr=0x000012de ordinal=034 sz=26 len=25 section=.data type=ascii string=hxp{n0th1ng_t0_h1de_h3r3}
vaddr=0x006012f8 paddr=0x000012f8 ordinal=035 sz=24 len=23 section=.data type=ascii string=hxp{such_n0fl4g_wowh4x}
```

OK so let's see what's happening at `obj.shc`

```
      0x00601310      8db600000000   lea esi, [rsi]
      0x00601316      8d742600       lea esi, [rsi]
      0x0060131a      8db426000000.  lea esi, [rsi]
      0x00601321      8dbc27000000.  lea edi, [rdi]
      0x00601328      4889d8         mov rax, rbx           ; rbx is the input
      0x0060132b      8a4000         mov al, byte [rax]
      0x0060132e      2440           and al, 0x40           ; check condition on first input byte
 ┌──< 0x00601330      7416           je 0x601348            ; jumps to exiting code
 ││   0x00601332      488d35340000.  lea rsi, 0x0060136d
 ││   0x00601339      ad             lodsd eax, dword [rsi]
 ││   0x0060133a      4889c1         mov rcx, rax
 ││   0x0060133d      ad             lodsd eax, dword [rsi] ; loads
┌───> 0x0060133e      3106           xor dword [rsi], eax   ; repeatedly XOR the values at rsi
│││   0x00601340      4883c604       add rsi, 4
└───< 0x00601344      e2f8           loop 0x60133e          ; decrement rcx
┌───< 0x00601346  ~   eb2d           jmp 0x601375
```

We can see that first a simple check on the input is performed with the `and`
instruction. The `je` jumps to code that prints `:(` and exits. So we want to
avoid that. Then the code decrypts the next part of the code using a simple
XOR. The key is prepended to data that get's decrypted.

So we could use the debugger to see what's going on. But I used the esil
emulation feature of radare2 to emulate the "decryption".

```
[0x00601332]> e io.cache=true
[0x00601332]> aei
[0x00601332]> ar0
[0x00601332]> aeim
[0x00601332]> aeip
[0x00601332]> aecu 0x00601346
ADDR BREAK
```

Unfortunately this really tok quite a while on my notebook. Let's look at the
decrypted code.

```
   ││   0x00601375      8d742600       lea esi, [rsi]
   ││   0x00601379      4889d8         mov rax, rbx
   ││   0x0060137c      8a401d         mov al, byte [rax + 0x1d]
   ││   0x0060137f      2402           and al, 2
  ┌───< 0x00601381      7416           je 0x601399
  │││   0x00601383      488d35340000.  lea rsi, 0x006013be
  │││   0x0060138a      ad             lodsd eax, dword [rsi]
  │││   0x0060138b      4889c1         mov rcx, rax
  │││   0x0060138e      ad             lodsd eax, dword [rsi]
 ┌────> 0x0060138f      3106           xor dword [rsi], eax
 ││││   0x00601391      4883c604       add rsi, 4
 └────< 0x00601395      e2f8           loop 0x60138f
 ┌────< 0x00601397      eb2d           jmp 0x6013c6
```

So this looks exactly the same as the previous code, just with slightly
different checks...

```
[0x00601375]> is~shc
vaddr=0x00601310 paddr=0x00001310 ord=068 fwd=NONE sz=150669 bind=GLOBAL type=OBJECT name=shc
```

At this point I realized why it's called zwiebel (onion in german btw.) and Oh
god this is a huge onion... I checked that the next few layers of the zwiebel
also look pretty much the same and assumed that they all do. I automated and
optimized the XOR decryption a little. I created a python script that used
`r2pipe` to talk to radare. I used ESIL emulation to single step up to the
first XOR it finds. Then extract the relevant information from the registers.

- `rax` always contained the key.
- `rsi` always contained a pointer to the data
- `rcx` always contained the length in `int32`

I then extracted the bytes from the layer and applied the XOR in python. I then
wrote back the bytes into radare2. The I started the whole process again at the
address of the decrypted code. I'm gonna attach a similar script at the end.

This allowed me to create a decrypted version of zwiebel. The end of the
decrypted code seems to be at `0x0062543c` with the last zwiebel decryption
happening at `0x006253f9`. The last piece of code prints a smiley string and 
then exits.

```
0x0062543c      683a290a00     push 0xa293a      ; pushes str ":)\n\x00"
0x00625441      b801000000     mov eax, 1        ; write syscall nr
0x00625446      bf00000000     mov edi, 0
0x0062544b      4889e6         mov rsi, rsp
0x0062544e      ba03000000     mov edx, 3
0x00625453      0f05           syscall
0x00625455      b83c000000     mov eax, 0x3c     ; exit syscall nr
0x0062545a      bf00000000     mov edi, 0
0x0062545f      0f05           syscall
```

So apparently this is the end and we have to reach this. So they really want us
to find the input. But since this is a huge amount of comparisons (we have 1605
zwiebel layers) we cannot do this manually. We need to get
[angr(y)](http://angr.io).

I wasn't sure whether angr could handle self modifying code, so I adapted my
zwiebel ~~decryption~~ peeling script to patch out the XORing. This way I could
just throw it into angr and hope for the best... and it revealed the flag:

```
hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}
```

Here are the scripts to unpeel the zwiebel with radare and to solve the
constraints using angr.

```python
#!/usr/bin/env python

from __future__ import print_function
import sys
import r2pipe
import datetime
import struct
import sys
import subprocess as sp
from sys import exit

# for interactive use:
# r2 = r2pipe.open()
# r2.cmd('e io.cache=true')
# batch use:
sp.check_call(['cp', 'zwiebel', 'zwiebel_test3'])
r2 = r2pipe.open("./zwiebel_test3")
# write to file directly without caching
r2.cmd('e io.cache=false')
r2.cmd('oo+')
r2.cmd('e asm.emu=false')

r2.cmd('aa')
r2.cmd('s obj.shc')


def decrypt_xor(fname='./layerX'):
    r2.cmd('ar0')   # clear all regs
    r2.cmd('aei')   # new esil vm state
    r2.cmd('aeim')  # esil stack
    r2.cmd('aeip')  # init rip to current seek

    r2.cmd('aes')  # esil step
    curop = r2.cmdj('pdj 1 @ rip')[0]

    # 1. step with esil until we hit a XOR instruction
    for i in range(0x10):
        if curop['opcode'].startswith('xor'):
            break

        if curop['opcode'].startswith('je') \
                or curop['opcode'].startswith('jne'):
            # skip the jump, esil might jump to the target, but we don't want
            # that.
            r2.cmd('ar rip={}'.format(curop['offset'] + curop['size']))

        r2.cmd('aes')
        curop = r2.cmdj('pdj 1 @ rip')[0]
    else:
        print("no xor instruction in the first 0x10 instructions")
        r2.cmd("s rip")
        return False

    # 2. extract the interesting info out of the esil registers
    regs = r2.cmdj('arj')
    data_addr = regs['rsi']
    key = regs['rax']
    size = regs['rcx']  # this is # of int32
    size_raw = size * 4  # size in bytes

    # seek to esil rip = the XOR instruction
    r2.cmd("s rip")
    # skip the XORing by patching it out and jumping directly to decrypted code
    # we also set rcx to zero, because that's the loop exit condition
    r2.cmd("\"wa xor rcx, rcx;jmp {}\"".format(data_addr))

    print()
    print("data =", hex(data_addr), "size =", hex(size_raw))
    print("key =", hex(key))

    # 3. extract the "encrypted" bytes
    # get array of bytes from radare
    data = r2.cmdj('p8j {} @ {}'.format(size_raw, data_addr))
    if data is None:
        print("nope that doesn't work")
        exit(-1)
    x = map(chr, data)
    print("length:", hex(len(data)))
    raw_data = "".join(x)  # join to string
    # unpack data as int32 list
    ints = struct.unpack("{}I".format(size), raw_data)
    
    # 4. "decrypt" the data using the extracted XOR and write back to r2
    ints_dec = map(lambda x: x^key, ints)
    # convert decrypted ints to bytes and write to file
    raw_data_dec = struct.pack("{}I".format(size), *ints_dec)
    with open(fname, "wb") as f:
        f.write(raw_data_dec)
    # seek to address of decrypted data and write back to r2
    r2.cmd("s {}".format(data_addr))
    r2.cmd("wf {}".format(fname))

    return True


print("start:", datetime.datetime.now().isoformat())
i = 0
print("decrypting zwiebel ring {}".format(i))
while decrypt_xor():
    i += 1
    print("decrypting zwiebel ring {}".format(i))
r2.cmd("s rip")
print("Last RIP at", hex(r2.cmdj("arj")["rip"]))
print("end:", datetime.datetime.now().isoformat())
```

truncated output:

```
[...]
decrypting zwiebel ring 1604
Cannot create mem here, mem allready lives herer_io_write: cannot write 8 bytes at 0xfffffffffffffff8 (file=./zwiebel_test3, fd=9)
hint: try oo+ or e io.cache=true
ESIL TRAP type 4 code 0xfffffff8 write-err
TRAP
no xor instruction in the first 0x10 instructions
Last RIP at 0x625405
[...]
```

the angr script:

```python
#!/usr/bin/env python

import angr
from claripy import BVS, And, Or

fname = './zwiebel_test3'
lo = {"auto_load_libs": False}
proj = angr.Project(fname, load_options=lo)

# length = 0x90  # input size of fgets
length = 64  # assume that the flag is not larger than this for now...
flag = BVS("flag", length * 8)  # create symbolic bitvector

# create a initial state
initial_state = proj.factory.blank_state(addr=0x00601328)
# store the stuff somewhere in memory
initial_state.memory.store(0x1000, flag)
initial_state.memory.store(0x2000, 0x1000, 64)
initial_state.memory.store(0x3000, 4, 64)
initial_state.regs.rbx = 0x1000
initial_state.regs.rsi = 0x00601310
initial_state.regs.rdx = 0x24c90
initial_state.regs.rsp = 0xffffff
initial_state.memory.store(initial_state.regs.rsp, 0x41414141, 64)

# set constraints on the bytes we know about
for i, byte in enumerate(flag.chop(8)):
    if i == 0:
        initial_state.add_constraints(byte == 'h')
    elif i == 1:
        initial_state.add_constraints(byte == 'x')
    elif i == 2:
        initial_state.add_constraints(byte == 'p')
    elif i == 3:
        initial_state.add_constraints(byte == "{")
    elif i == (length - 1):
        initial_state.add_constraints(byte == "\x00")
    else:
        # usually flags are printable
        initial_state.add_constraints(Or(And(' ' <= byte, byte <= '~'), byte == 0))

# create a path group based on the initial state
path_group = proj.factory.path_group(initial_state)

# explore until we reach the smiley printing code
path_group.explore(find=0x0062543c)

for found in path_group.found:
    for s in found.state.se.any_n_str(flag, 8):
        print s

# print some stats
for k, v in path_group.stashes.iteritems():
    print(k, len(v))
```

output:

```
hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}????g?7???>?????/??
hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}???=g?7_??>?????/??
hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}????o?????>?????/??
hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}????o??????????????
hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}????o?????>????????
hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}
hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}????g?????>?????/??
hxp{1_h0p3_y0u_d1dnt_p33l_th3_0ni0n_by_h4nd}???????????????????
('pruned', 0)
('deadended', 1602)
('avoid', 0)
('stashed', 0)
('unsat', 0)
('active', 2)
('found', 1)
('errored', 0)
('unconstrained', 0)
```
