---
layout: post
title:  "hack.lu CTF 2014: Killy The Bit"
author: f0rki
categories: writeup
tags: [cat/web, lang/php]
---

## Write-up

This was a fun challenge :) The setting was that the royal bank of Fluxembourg
was hacked by Killy the Bit and now they set up a page to reset the user
passwords. Because Killy owes us a favor we received the source code for the
password resetting page. So the whole thing was php using mysql as a database.
Inspecting the source you can easily spot the SQL injection vulnerability.  But
finding it wasn't the challenge, actually exploiting it was.


```php
<?php
include 'config.php';

// unintersting HTML output truncated

//<!-- blind? we will kill you :) -->
    if(isset($_GET['name'])
        && $_GET['name']!=''
        && !preg_match('/sleep|benchmark|and|or|\||&/i',$_GET['name']))
    {
        $res = mysql_query("SELECT name,email FROM user where name='".$_GET['name']."'");

        if(mysql_fetch_object($res)) {
            // Generation of new password
            //<topsecure content>
            // this was filtered during the creation of the phps file
            //</topsecure content>
            die("A new password was generated and sent to your email address!");
        } else {

            $res = mysql_query("SELECT name,email FROM user where name sounds like '".$_GET['name']."'");

            if(mysql_fetch_object($res)) {
                echo "We couldn't find your username, but it sounds like this user:<br>";
            } else {
                die("We couldn't find your username!<br>Are you sure it is ".htmlspecialchars($_GET['name'],ENT_QUOTES, 'utf-8')."?");
            }
            $res = mysql_query("SELECT name,email FROM user where name sounds like '".$_GET['name']."'");

            while($row = mysql_fetch_object($res)) {
                echo $row->name;
                echo "<br>";
            }
        }
    } else {
        // uninteresting HTML output truncated
    }
?>
```

As you can see on line 9 we cannot use and, or, sleep and benchmark in the
query which makes exploiting this a little tricky. In total the whole script
performs three queries. We do not see any output of the first two queries. Of
course we could do a blind SQL injection here, but this is made harder by the
preg_match filter. As it turns out we can craft an input so that the first
query returns 0 rows, the second one returns 1 row and the last query returns
all the possible rows. The key to this is the 'sounds like' part of the
last two queries. 'a sounds like b' is a shortcut for 'soundex(a)=soundex(b)'.


    > select soundex('admin'), soundex('admni');
    +------------------+------------------+
    | soundex('admin') | soundex('admni') |
    +------------------+------------------+
    | A350             | A350             |
    +------------------+------------------+


Now we can get to the last the query by using 'admni' as the value for the
name column in the where part of the query. Now we need to use union select
to actually fetch data. Unfortunately just simply injecting the following

    admni' union select passwd, email from user -- x

makes the first query to succeed and we don't see any output. So we need to
find a way to restrict the union select to return 0 rows in the first query.
Fortunately there exists the
[found_rows function ](https://mariadb.com/kb/en/mariadb/documentation/functions-and-operators/information-functions/found_rows/)
in mysql, which returns the number of rows found by the last query.
By injecting the following we can get the first query to return 0 rows and
thus we get to the interesting else branch.

    admni' union select passwd, email from user where found_rows() > 0 -- x

1. query: returns 0 rows, name='admni' is false, found_rows() is 0
2. query: return 1 row, sounds like 'admni' returns 1 result ('admin'),
   found_rows() is 0
3. query: returns lots of rows, souds like 'admni' is true, found_rows() is 1
   and therefore we get everything in the passwd column.

...and we got the flag :)

    flag{Killy_The_Bit_Is_Wanted_for_9000_$$_FoR_FlipPing_Bits}
