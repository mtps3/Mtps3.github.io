---
title: 'hack.lu CTF 2014: Hidden In Plain Sight'
date: 2014-10-26 00:00:00 Z
categories:
- writeup
tags:
- cat/crypto
- lang/javascript
layout: post
author: f0rki
---

## Write-up

OK I have to confess I solved this challenge by pure luck. The setting was that
there is a service that allows you to register and the upload files. The
uploaded files can be shared by creating a link, which contains a HMAC over the
user and the filename. If we know the hmac over the user and the file, we can
access the file. We are asked to access the 'testuser/flag.txt' file.  So the
whole code makes a pretty decent impression in terms of security. There are no
obvious vulnerabilities.

We were asked to find a backdoor and the challenge was tagged as a crypto
challenge and HMAC key generation looked a little fishy so I copy & pasted it
into a local file to see what the HMAC secret would look like. And what a
surprise the HMAC_SECRET variable was set to empty string. WTF. So first I went
on to get the flag. Later on I noticed that the 'E' in the HMAC_SECRET on the
left-hand side of the assignment in the loop was in fact a unicode character
that looks like an 'E'.

```javascript
// copy & pasted hmac secret generation
var HMAC_SECRET = ''
for (var i=0; i<20; i++) {
  HMAC_SΕCRET = HMAC_SECRET + (Math.random()+'').substr(2)
}
//
/* relevant xxd output. Mind the unicode char that looks like 'E'!
0000030: 3d 20 27 27 0a 66 6f 72 20 28 76 61 72 20 69 3d  = ''.for (var i=
0000040: 30 3b 20 69 3c 32 30 3b 20 69 2b 2b 29 20 7b 0a  0; i<20; i++) {.
0000050: 20 20 48 4d 41 43 5f 53 ce 95 43 52 45 54 20 3d    HMAC_S..CRET =
0000060: 20 48 4d 41 43 5f 53 45 43 52 45 54 20 2b 20 28   HMAC_SECRET + (
0000070: 4d 61 74 68 2e 72 61 6e 64 6f 6d 28 29 2b 27 27  Math.random()+''
0000080: 29 2e 73 75 62 73 74 72 28 32 29 0a 7d 0a 0a 0a  ).substr(2).}...
*/

console.log("the hmac is:")
console.log(HMAC_SECRET)
console.log("------")
// holy shit it's empty string :o

// copy&pasted signing function
var crypto = require('crypto')
function hmac_sign(path) {
  var hmac = crypto.createHmac('sha256', HMAC_SECRET)
  hmac.update(path)
  return hmac.digest('hex')
}

console.log("generated hmac:")
console.log(hmac_sign("testuser/flag.txt"))
```

After running this with node we get the HMAC and obtaining the flag is simply a
matter of:

    $ curl https://wildwildweb.fluxfingers.net:1409/files/testuser/flag.txt/4a332c7f27909f85a529393cea72301393f84cf5908aa2538137776f78624db4
    flag{unicode_stego_is_best_stego}
