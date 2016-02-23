---
layout: post
title:  "Internetwache CTF 2016: Hashdesigner (crypto 70)"
author: creed
categories: writeup
tags: [cat/crypto, tools/pwntools]
---

* **Category:** Crypto
* **Points:** 70
* **Solves:** 89
* **Description:**

> Description: There was this student hash design contest. All submissions were crap, but had promised to use the winning algorithm for our important school safe. We hashed our password and got '00006800007d'. Brute force isn't effective anymore and the hash algorithm had to be collision-resistant, so we're good to go, aren't we?

## Write-up

Given was a python script which contained an implementation of a custom hash function. One part stood out almost immidiately, since it also has a comment beside it:

```python
  t11 = t11 % 0xFF # Should be 0xFFFFFFFF, right?
  q2 = q2 % 0xFF # Same here... 0xFFFFFFFF

  return tp(t11,q2)
```
This is the finalization of the hash function, which seems like it is supposed to calculate two 32-bit values and concat them in the function tp().
However, like the comments say, the modulus is only 0xFF, meaning that there are only 2^16 possible hash values instead of the intended 2^64.

Since we know the value of the admin password hash from the description ('00006800007d') we can just use a brute-force approach to find a colliding hash, which due to the low number of possible hashes should be pretty easy.

The following python snippet does exactly that (it also already generates length 18 passwords, which the login system later told us was a requirement):

```python
  while 1:
   s = ""
   for _ in range(18):   #pw has to be at least 18 chars long
     s += random.choice(string.letters+string.digits)
   if myhash(s) == '00006800007d':
     print s
     break;
```
This gave us the colliding input 'DhvxGXEdJkRiv4QEDS'.

So all that was left to do was to log into the system with our new password. However, upon connecting to the provided ip, we were presented with a classic proof of work challenge.

Since we have encountered countless of these before, we just adapted our existing code to satisfy the challenge and upon sending our colliding password, we were presented with the flag.

The python code used to calculate that proof of work and send the password can be found [on GIST](https://gist.github.com/dkales/d396c0318d12e93d89fa).
