---
title: 'Sharif University CTF 2016: Blocks (forensics 400)'
date: 2016-02-07 00:00:00 Z
categories:
- writeup
tags:
- cat/forensics
- lang/sql
- tech/png
layout: post
author: f0rki
---

* **Category:** forensics
* **Points:** 400
* **Description:**

> I recovered as much data as I could. Can you recover the flag?


## Write-up


We are given a data blob. `file` doesn't find any magic values it recognizes.
Inspecting the file we can see some SQL commands inside the binary blob. So it
looks like this is an sqlite file, which lacks it's header. Of course we cannot
simply open it with the `sqlite` command.

To be able to query the sqlite file we copied the header of a intact sqlite
file in front of the `data1` file and we can now open it successfully.

```
sqlite> .schema
CREATE TABLE `category` (
	`ID`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`Cat`	TEXT NOT NULL
);
CREATE TABLE "data" (
	`ID`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	`Data`	BLOB NOT NULL,
	`Cat`	INTEGER NOT NULL
);
```

Let's see what's in the tables.

```
sqlite> select * from data limit 1;
1|D�M2��T�[,�4�q��HR�`����&��0�PrE�w�d�\�J��R8��gV��V�G���2$�s���@��������3�ae�g�+ª~�{_�;C���u���YD�&DrH҇H�� F,�����ke�\�f�"�s��9/�M�V��j;_u��Ί8A�|2�F�\

select * from category;
1|CHRM
2|IDAT
3|ICCP
4|IHDR
5|TEXT
6|TIME
7|PLTE
8|TRNS
```

OK So there is binary data in the data table. We recognized the category names
as [PNG chunk types](https://www.w3.org/TR/PNG/#4Concepts.FormatTypes). So
maybe the binary data in the data column of the data table are chunks ofa PNG
image. So we first dumped all the blobs from sqlite to files. We used the
following script:

```python
import sqlite3

conn = sqlite3.connect('repaired.db')
c = conn.cursor()

q = 'select d.ID, d.Data, C.Cat from data d JOIN category c on d.Cat = c.ID;'
for row in c.execute(q):
    with open("out/{}_{}".format(row[0], row[2]), "w") as f:
        f.write(row[1])

c.close()
conn.close()
```

We get the following files:

```
$ ls out
10_IDAT  12_IDAT  14_PLTE  2_IDAT  4_IDAT  6_IDAT  8_IDAT
11_IDAT  13_IDAT  1_IDAT   3_IDAT  5_IDAT  7_IHDR  9_TRNS
```

We read up a little on the PNG file format and started to investigate the chunk
data. So a chunk in PNG consists of

```
length | chunk type | data | CRC32
```

We couldn't find a length and also not the chunk type, which are actually
readable, so we should've been able to see them in the hexdumps. Our guess was
that also the CRC32 is missing. Maybe we can reconstruct the PNG from the given
data. From the PNG spec we know that the chunks must be in a specific order.
First comes the `IHDR` chunk, then `PLTE` and `TRNS`. So we already know the
first few chunks. We created a python script that throws together the PNG files
from the raw binary data. We used the `pngcheck` tool to get error message on
what is wrong with the image.

 1. Write png magic value
 2. Write `IHDR` chunk
 3. Write `PLTE` chunk
 4. Write `TRNS` chunk
 5. Write `IDAT` chunks in the order of their database IDs
 6. Write `IEND` chunk


Unfortunately this did give us some decompression error. First we tried to
compress the data of the IDAT chunks, but this just yielded more errors. So no
luck here. Then we tried to order the `IDAT` chunks differently. We got a
different error message with the `3_IDAT` chunk at the beginning. OK so maybe
we just need to find the right order of chunks.

Our first instinct was to somehow check all permutations of IDAT chunks and see
if this would yield some result, but this was soon discarded as that would be
quite a lot of images.

We took a look at the PNG with the `3_IDAT` chunk in the beginning and the
other chunks ordered by their database id. This just resulted in an error in
most of our images viewers. Fortunately my colleague took a look at the image
with `feh`. There We could make out the beginning of something that looked like
text, probably the flag. `gimp` was also able to decode and display parts of
the PNG. The view in gimp looked like this:

![](/images/posts/2016-02-07-sharifctf2016-blocks_1.png)

OK So now we only need to find the next `IDAT` chunk that gives us some result
that looks reasonable. So our workflow was:

 - Try different `IDAT` chunk at last unknown position
 - Look at picture in `gimp`
 - Keep `IDAT` at this position if more of the flag is visible
 - If no `IDAT` chunk results in more, then backtrack and try another chunk on
   previous position.

Because we were two people doing this in parallel, we were quite fast at this.
At the end we got the PNG, which contained the flag as text. We just had to
mirror it one time and then we could just read the flag:

![](/images/posts/2016-02-07-sharifctf2016-blocks_2.png)


This is the script we used for building the PNG file:

```python
#!/usr/bin/env python

from __future__ import print_function
from zlib import crc32
from struct import pack


pngname = "./out.png"
png = open(pngname, "w")

png.write('\x89PNG\x0d\x0a\x1a\x0a')

types = {}
IHDR = "".join(map(chr, [73, 72, 68, 82]))
PLTE = "".join(map(chr, [80, 76, 84, 69]))
TRNS = "".join(map(chr, [116, 82, 78, 83]))
IDAT = "".join(map(chr, [73, 68, 65, 84]))
IEND = "".join(map(chr, [73, 69, 78, 68]))


def write_chunk(ctype, fname, prependix="", appendix=""):
    print(ctype, fname)
    data = ""
    if fname:
        with open(fname) as f:
            data = f.read()
        if prependix:
            data = prependix + data
        if appendix:
            data = data + appendix
    png.write(pack(">I", len(data)))
    png.write(ctype)
    png.write(data)
    c = crc32(ctype + data)
    #print(c)
    c = pack(">i", c)
    png.write(c)


write_chunk(IHDR, "./out/7_IHDR")
write_chunk(PLTE, "./out/14_PLTE")
write_chunk(TRNS, "./out/9_TRNS")

# found the order by trial-and-error (aka look at png in gimp)
idats = """
./out/3_IDAT
./out/10_IDAT
./out/4_IDAT
./out/6_IDAT
./out/13_IDAT
./out/8_IDAT
./out/12_IDAT
./out/5_IDAT
./out/1_IDAT
./out/2_IDAT
./out/11_IDAT
""".strip().split("\n")

for fn in idats:
    if fn:
        write_chunk(IDAT, fn)

write_chunk(IEND, None)

png.close()
```
