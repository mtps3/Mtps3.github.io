---
layout: post
title:  "Sharif University CTF 2016: sec-coding1 (misc 100)"
author: f0rki
categories: writeup
tags: [cat/misc, lang/cpp]
---

* **Category:** misc
* **Points:** 100
* **Description:**

> You should fix vulnerabilities of the given source code, WITHOUT changing its
> normal behaviour.

## Write-up

So that task is to fix all vulnerabilities in a given C++ program:

```cpp
#include <vector>
#include <iostream>
#include <windows.h>

using namespace std;

int main() {
    vector<char> str(MAX_PATH);

    cout << "Enter your name: ";
    cin >> str.data();

    cout << "Hello " << str.data() << " :)" << endl;

    return -14;
}
```

Pretty short and pretty obvious what's wrong with this program. `str` is a
vector of `char` with `MAX_PATH` entries preallocated. Then the name is read
from `cin` into `str.data()`, which is a
[raw pointer to the underlying storage](http://en.cppreference.com/w/cpp/container/vector/data)
of vector (aka `char*`). Using the raw pointer there is no bounds checking and
no allocation of additional memory, so this is a classic buffer overflow.
Replacing the vector with a `string` solves this issue.

```cpp
#include <iostream>
#include <string>

using namespace std;

int main()
{
    //vector<char> str(MAX_PATH);
    string str;

    cout << "Enter your name: ";
    cin >> str;

    cout << "Hello " << str << " :)" << endl;

    return -14;
}
```

After submitting the fixed program, we got the flag.

Easy and obvious... at least if you know anything about C/C++. This seems more
like a 10 point warm up challenge than 100 points... well.
