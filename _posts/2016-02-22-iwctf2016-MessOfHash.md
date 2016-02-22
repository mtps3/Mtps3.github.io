---
layout: post
title:  "Internetwache CTF 2016: Mess Of Hash (web 50)"
author: kree
categories: writeup
tags: [cat/web, lang/php]
---

* **Category:** web
* **Points:** 60
* **Description:** 

> Students have developed a new admin login technique. I doubt that it's secure, but the hash isn't crackable. I don't know where the problem is...

* **Hint (README.txt):** 

```php
<?php

$admin_user = "pr0_adm1n";
$admin_pw = clean_hash("0e408306536730731920197920342119");

function clean_hash($hash) {
    return preg_replace("/[^0-9a-f]/","",$hash);
}

function myhash($str) {
    return clean_hash(md5(md5($str) . "SALT"));
}
```

## Writeup

The website shows a login form with a user and a password field. From the given hint in the README file we can assume that we need to find a value for the password field that gets us through the following check:

```php
md5(md5($str) . "SALT")) == "0e408306536730731920197920342119"
```

In order to solve this challenge we could look for a md5 collision, but in this case there's an easier way: The `==` operator offers some exploitable magic in php. As described here [1], a string that starts with `0e` will be interpreted as a float and converted to `0`. So, one needs to find a `$str` such that `md5(md5($str) . "SALT"))` starts with `0e` and thats it :) 

The following script

```php
<?php
$i = 0;
do{
    $i++;
} while(md5(md5(strval($i))."SALT") != "0e408306536730731920197920342119");
echo $i;
?>
```

yields `62778807` after a few seconds, which we can use as a password.

Flag:  `IW{T4K3_C4RE_AND_C0MP4R3}`

[1] https://news.ycombinator.com/item?id=9484757
