---
layout: post
title:  "Sharif University CTF 2016: sec-coding2 (misc 300)"
author: f0rki
categories: writeup
---

* **Category:** misc
* **Points:** 300
* **Description:**

> You should fix vulnerabilities of the given source code, WITHOUT changing its
> normal behaviour.

## Write-up

So that task is to fix all vulnerabilities in a given C++ program. Their
definition of vulnerabilities was sometimes a little strange, but OK. The
program we are given does a very sketchy parsing of it's command line
parameters. I annotated some problems in the source below with `///`

```cpp
#include <math.h>
#include <stdio.h>
#include <windows.h>


int main(int argc, char **argv)
{
	// STRING ECHO
	//
	// Sample usage:
	//   strecho repeat=4,str=pleaseechome

    /// it's C++ damnit, why use malloc?
	char *str = (char *)malloc(100);
    /// should probably be unsigned
	int repeat = 0;

    /// why not use argv?
	char *line = GetCommandLineA();

	while (*line != ' ')
		line++;
	line++;

	if (strncmp(line, "repeat=", 7) == 0)
	{
		line += 7;
        /// atoi can't signal errors
		repeat = atoi(line);
        /// wtf?
		line += (int)ceil(log10((double)repeat)) + 1;
	}

	if (strncmp(line, "str=", 4) == 0)
	{
		line += 4;
        /// this results in invalid free and memleak later
		str = strtok(line, " ");
	}

	for (int i = 0; i < repeat; i++)
		printf("%s\n", str);

    /// this loop just doesn't make any sense at all
	line += strlen(str);
	for (; line >= GetCommandLineA(); line--)
		*line = '\x0';

	free(str);

	return -14;
}
```

Again a quick rewrite with proper C++ types and checking every even so stupid
possible error condition. Important was to give some output. Return codes
didn't matter at all, but you had to output some error message, so that they
would detect the "vulnerability" as fixed.

```cpp
#include <limits.h>
#include <stdlib.h>
#include <iostream>


using namespace std;

int main(int argc, char **argv)
{
  // STRING ECHO
  //
  // Sample usage:
  //   strecho repeat=4,str=pleaseechome

  string str = "";
  unsigned long repeat = 0;

  if (argc != 2) {
    cout << "invalid arg count" << endl;
    return -1;
  }

  if (argv[1] == NULL) {
    cout << "argcount and argv don't match" << endl;
    return -1;
  }

  string line(argv[1]);

  if (line.empty()) {
    cout << "empty args";
    return -1;
  }

  if (line.find("str=") == string::npos
      || line.find("repeat=") == string::npos) {
    cout << "invalid input" << endl;
    return -1;
  }

  if (line.find("str=") < line.find("repeat=")) {
    cout << "invalid input" << endl;
    return -1;
  }


  string repeat_s = line.substr(line.find("repeat=") + 7, line.find(","));

  if (repeat_s.empty()) {
    cout << "empty repeat" << endl;
    return -1;
  }
  if (repeat_s.find("-") != string::npos) {
    cout << "negative repeat" << endl;
    return -1;
  }

  //repeat = stoul(repeat_s);
  repeat = strtoul(repeat_s.c_str(), NULL, 10);
  if (repeat == ULONG_MAX) {
    cout << "int parsing fail" << endl;
    return -1;
  }
  if (repeat == 0) {
    cout << "repeat should be bigger than 0" << endl;
    return -1;
  }

  str = line.substr(line.find(",str=")+5, line.size());

  if (str.empty()) {
    cout << "no string found" << endl;
    return -1;
  }

  for (unsigned long i = 0; i < repeat; i++) {
    cout << str << endl;
  }

  return 0;
}
```

We were stuck with the message `There is 1 vulnerability(ies) left` for a long
time and couldn't figure out what it was. Apparently passing a `repeat=0` on
the commandline was considered a vulnerability. I didn't give any error message
and just did an early return, because repeating a string 0 times, obviously
gives no output, but imho isn't a problem. This was the last "vulnerability"
that we needed to fix.

After submitting the fixed program, we got the flag.
