---
layout: post
title:  "hack.lu CTF 2014: Objection"
author: f0rki
categories: writeup
tags: [tech/nodejs, lang/javascript]
---

## Write-up

So we got the source for something that looked like CoffeeScript, but had
really strange string literals. After some investigation I found out, that
this was in fact (coco)[https://github.com/satyr/coco] source code.
Coco in turn is a fork of (CoffeeScript)[http://coffeescript.org/]. Both
compile to JavaScript.
The service allows you to login with the admin password that is read from a
file. If the user is authenticated as admin, he can read the secret token
using the get_token function. The following source file was provided.

```coffeescript
const net = require \net
const BufferStream = require \bufferstream

admin_password = (require \fs).readFileSync \admin_password, \utf8


server = net.createServer (con) ->
  console.log 'client connected'
  con.write 'hello!\n'
  client_context =
    is_admin: false
    token: (require \fs).readFileSync \secret_token, \utf8
    login: ([password], cb) ->
      if password == admin_password
        cb "Authentication successful  " + password
        @is_admin = true
      else
        cb "Authentication failed  " + password
    get_token: ([], cb) ->
      if not @is_admin then return cb "You are not authorized to perform this action."
      cb "The current token is #{@token}"
  console.log client_context
  in_stream = new BufferStream {encoding:\utf8, size:\flexible}
  con.pipe in_stream
  <- in_stream.split \\n
  it .= toString \utf8
  console.log "got line: #{it}"
  [funcname, ...args] = it.split ' '
  if typeof client_context[funcname] != \function
    return con.write "error: unknown function #funcname\n"
  client_context[funcname] args, ->
    con.write "#it\n"

server.listen 1408, ->
  console.log 'server bound'
```

The whole thing is a kind of sandbox escape, since the command are implemented
by calling methods on the 'client_context' object. The input string is split on
the space character and the first token is the function name. So we can
actually call an arbitrary function on the object. All further tokens are
passed as a string array. So we cannot inject code or something like that.
But wait, let's look at how the the methods of the object are called exactly.

    client_context[funcname] args, ->
      con.write "#it\n"

First the function is accessed via the name as a string. args is an array of
strings. Then a callback function is passed as the last argument. The '->'
arrow is CoffeeScript/coco shorthand for defining a function. The '#it' in the
string is syntax for string expansion using the 'it' variable. Because this
variable isn't declared anywhere in the function body coco infers that it must
be an argument to the function. As you can see in this example:

    $ coco -bce '-> console.log "#it\n"'
    (function(it){
      return console.log(it + "\n");
    });

Now to the interesting part: how to get the flag. Let's have a look what
functions a plain object in JavaScript has. So let's fire up a node.js
interpreter and poke around a little bit by hitting tab.

    > x = {}
    {}
    > x.
    x.__defineGetter__      x.__defineSetter__      x.__lookupGetter__      x.__lookupSetter__
    x.constructor           x.hasOwnProperty        x.isPrototypeOf         x.propertyIsEnumerable
    x.toLocaleString        x.toString              x.valueOf


(__defineGetter__)[https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/__defineGetter__]
seems useful, since the properties 'is_admin' and 'token'
are accessed (you can spot properties in CoffeeScript and coco by the @
prefix). It expects the following arguments

    obj.__defineGetter__(sprop, fun)

Where sprop is the property name and fun is the getter function. This matches
exactly the call of the function in the source file we got. So we can pass the
anonymous callback function as a getter. Since this function takes an argument
'in' as parameter, calling the function without any argument results in 'it'
just being undefined. Concatenating an undefined variable with a string
results in the string "undefined" + the other string. So let's define the
getter for 'is_admin' by sending the following string to the service.

    __defineGetter__ is_admin

Now if is_admin is accessed, instead the anonymous callback function is
called. Remember it looks like this in CoffeeScript

    -> con.write "#it\n"

In CoffeeScript/coco the last expression is also the return value of a
function. The anonymous function compiled to JavaScript looks like this:

    function(it){
        return con.write(it + "\n");
    }

This means this anonymous function will return the return value of the 'write'
method of the con object, which is an socket object. The
(socket.write)[https://nodejs.org/api/net.html#net_socket_write_data_encoding_callback].
function will return true if the entire data was flushed to the kernel buffer.
Since we only write the string "undefined\n", chances are pretty good this will
happen. So accessing the 'is_admin' property will in fact call this anonymous
callback function and return 'true'. On the way it will write "undefined\n",
but this doesn't matter since we are suddenly admin :)

    hello!
    __defineGetter__ is_admin
    get_token
    undefined
    The current token is flag{real_cowboys_dont_use_object_create_null}


Hooray :)
