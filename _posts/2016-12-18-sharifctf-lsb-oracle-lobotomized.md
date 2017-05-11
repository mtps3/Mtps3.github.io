---
title: 'SharifCTF 7: Lobotomized LSB oracle (crypto 400)'
date: 2016-12-18 00:00:00 Z
categories:
- writeup
tags:
- cat/crypto
layout: post
author: creed
---

* **Category:** crypto
* **Points:** 400
* **Description:**

> see the attachment
> http://ctf.sharif.edu/ctf7/api/download/32
>

## Write-up

This is the second version of the lsb_oracle challenge. (You can find the first version [here](https://losfuzzys.github.io/writeup/2016/12/18/sharifctf-lsb-oracle/))
We were again given a python file detailing the encryption process, which was again standard RSA with PKCS1 v1.5 padding. 

```python
#! /usr/bin/env python3
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long

n = 94169898764475155086179365872915864925768243050855426387910613522303337327416930459077578555524838413579345103633071500300104580298306187507383687796776619261744561887287065152410825040924957174425131901014950571780211869823508452987101620679856181308669517708916215765377471785309709279780997993371462202127
e = 65537L

flag = b'' # redacted
key = RSA.construct((n, e))
cipher = PKCS1_v1_5.new(key)
ctxt = bytes_to_long(cipher.encrypt(flag))

print(ctxt)
print(b)
# output is:
# 84554310261580598058211620872297995265063480196893812976334022270327838015482739129096939702314740821259766144865677921673974339162910708930818463109733348984687023660294660726179053438750361754457786927212462355725758670143043124242928370865662017903815787388480232771504943423128214544949007416507395402507
```

However, when trying the solution script for the first lsb_oracle, we notice that we get a part of the flag, but the
LSB oracle now gives random output for the 200 least siginificant bits, rendering a huge part of the flag unreadable.

Upon further inspection, I found out that other (non-flag) ciphertext work just fine for the LSB oracle, again only having a few corrupt bytes at the end.
Knowing this, we can use the property of RSA that it is homomorphic with respect to multiplication. This means that `ENC(P1*P2) == C1*C2`.

We generate another known plaintext-ciphertext pair, and multiply the two ciphertexts together. We can now decode this new ciphertext with the LSB oracle,
and bruteforce the last 3 bytes (which takes a few minutes) to get the correct plaintext. We then can multiply this plaintext with the inverse of our second
plaintext and get the flag plaintext. This process can be seen in the below script.

```python
#!/usr/bin/env python2 
from pwn import *

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes
import gmpy2

n = 94169898764475155086179365872915864925768243050855426387910613522303337327416930459077578555524838413579345103633071500300104580298306187507383687796776619261744561887287065152410825040924957174425131901014950571780211869823508452987101620679856181308669517708916215765377471785309709279780997993371462202127
e = 65537L

#second known 
mes = b'a'*(1024/8)
ctxt = pow(bytes_to_long(mes), e, n)

C= 84554310261580598058211620872297995265063480196893812976334022270327838015482739129096939702314740821259766144865677921673974339162910708930818463109733348984687023660294660726179053438750361754457786927212462355725758670143043124242928370865662017903815787388480232771504943423128214544949007416507395402507

NEWC = (C*ctxt) % n

oracle_process = process(["wine", "./lobotomized_lsb_oracle.vmp.exe", "/decrypt"])
def oracle(CIN):
    oracle_process.recvuntil("done.\r\n")
    oracle_process.sendline(str(CIN))
    ret= int(oracle_process.readline().strip())
    return ret


UP = n
LOW = 0

cur_C = NEWC 
for i in range(n.bit_length()):
    print i
    cur_C = (cur_C * (2**e % n)) %n
    if oracle(cur_C) == 0:
        UP = (UP + LOW)/2
    else:
        LOW = (UP + LOW)/2


inv_mes = gmpy2.invert(bytes_to_long(mes), n)
for i in range(256):
    print i,
    for j in range(256):
        for k in range(256):
            dat = long_to_bytes(UP)[:-3] + chr(i) + chr(j) + chr(k) 
            data = bytes_to_long(dat)
            Maybe = long_to_bytes((data*inv_mes) %n) 
            if "Sharif" in Maybe:
                print Maybe
```



```
SharifCTF{76a7e30ea5f3edd488182c4845a6858e}
```


