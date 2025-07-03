## Level Goal

The password for the next level is **stored somewhere on the server** and has all of the following properties:

    owned by user bandit7
    owned by group bandit6
    33 bytes in size

## Solution

Login ssh via terminal

``` 
ssh bandit.labs.overthewire.org -p 2220 -l username 
```
 
username : bandit6 <br>
password : HWasnPhtq9AVKe0dmk45nxy20cvUa6EG

use ```ls``` to check what is in the directory, the result is nothing is found. Then, I use ```pwd``` to check which directory I am in. It is known that I am in the following directory

/home/bandit6

Next, I move to the root directory using the command ```cd /```

This is done because the instructions for the question state that the password is stored somewhere on the server, so it is not limited to just the home directory. By being in the _root_, I can use the ```find``` command to search for the file throughout the system.

Then, use find with additional parameters according to the instructions, namely

    find -user bandit7 -group bandit6 -size 33c

Then many messages will appear in several directory files that **permission denied**, then search among the messages that do not contain the words **permission denied** then the file is obtained, namely

    .var/lib/dpkg/info/bandi7.password

Then, open the file using the command

    cat .var/lib/dpkg/info/bandi7.password

The password that can be obtained is : ```morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj```

[![6-7(1).png](https://i.postimg.cc/yd7RcYz3/6-7-1.png)](https://postimg.cc/nswMtxrn)

[![6-7(2).png](https://i.postimg.cc/gJ4ZDFYS/6-7-2.png)](https://postimg.cc/MMMH6LfV)