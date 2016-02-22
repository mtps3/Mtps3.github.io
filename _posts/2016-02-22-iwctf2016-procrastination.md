---
layout: post
title:  "Internetwache CTF 2016: Procrastination (crypto 80)"
author: sigttou
categories: writeup
tags: [cat/crypto]
---

* **Category:** crypto
* **Points:** 80
* **Description:** 

> Watching videos is fun! Hint: Stegano skills required.
> Service: https://procrastination.ctf.internetwache.org

## Write-up

Given was a website including a `song.webm` file. Running `mediainfo` got us the hint,
that there is a second audio trace inside the file.
We used `ffmpeg` to receive the audio file in `wav` format:

```
ffmpeg -i song.webm -map 0:2 out.wav
```

After listening to it, we concluded that it must be some dial-up noise. So we ran some DTMF analysis.

```
multimon-ng -t wav -a DTMF out.wav
```

This gave us some numbers separated by zeros:

```
111 127 173 104 122 60 116 63 123 137 127 61 124 110 137 120 110 60 116 63 123
```

We knew that it must be something like `IW{..}`.
So we looked in the ASCII Table and saw that this must be some OCT representation.


So the flag was `IW{DR0N3S_W1TH_PH0N3S}`.
