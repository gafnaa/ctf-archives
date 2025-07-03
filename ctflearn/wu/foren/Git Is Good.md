# Git Is Good

The flag used to be there. But then I redacted it. Good Luck. https://mega.nz/#!3CwDFZpJ!Jjr55hfJQJ5-jspnyrnVtqBkMHGJrd6Nn_QqM7iXEuc

## Solution

```php
$ git logs
git: 'logs' is not a git command. See 'git --help'.

The most similar command is
        log

┌──(gafnaa㉿WIN-VQ99FOIVV68)-[/mnt/e/CTF/ctflearn/files/gitIsGood/gitIsGood/.git/logs]
└─$ git log
commit d10f77c4e766705ab36c7f31dc47b0c5056666bb (HEAD -> master)
Author: LaScalaLuke <lascala.luke@gmail.com>
Date:   Sun Oct 30 14:33:18 2016 -0400

    Edited files

commit 195dd65b9f5130d5f8a435c5995159d4d760741b
Author: LaScalaLuke <lascala.luke@gmail.com>
Date:   Sun Oct 30 14:32:44 2016 -0400

    Edited files

commit 6e824db5ef3b0fa2eb2350f63a9f0fdd9cc7b0bf
Author: LaScalaLuke <lascala.luke@gmail.com>
Date:   Sun Oct 30 14:32:11 2016 -0400

    edited files

┌──(gafnaa㉿WIN-VQ99FOIVV68)-[/mnt/e/CTF/ctflearn/files/gitIsGood/gitIsGood]
└─$ git checkout 195dd65b9f5130d5f8a435c5995159d4d760741b -- flag.txt

┌──(gafnaa㉿WIN-VQ99FOIVV68)-[/mnt/e/CTF/ctflearn/files/gitIsGood/gitIsGood]
└─$ cat flag.txt
flag{protect_your_git}
```

## Flag
    flag{protect_your_git}