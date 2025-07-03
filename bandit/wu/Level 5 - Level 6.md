## Level Goal

The password for the next level is stored in a file somewhere under the inhere directory and has all of the following properties:

    human-readable
    1033 bytes in size
    not executable

## Solution

Login ssh via terminal

``` 
ssh bandit.labs.overthewire.org -p 2220 -l username 
```
 
username : bandit5 <br>
password : 4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw

use ```ls``` to check what is in the directory
then open **inhere** folder using ```cd inhere``` command

use ```ls``` again to check contents in folder, and it turns out there are several folders in it. So, to find where the file is, we can use this command

```
find -readable -size 1033c -not -executable
```
then we will got the file what we are looking for.
just open the file using ```cat ./maybehere07/.file2``` 

The password that can be obtained is : ```HWasnPhtq9AVKe0dmk45nxy20cvUa6EG```

[![5-6.png](https://i.postimg.cc/x8mjWxpL/5-6.png)](https://postimg.cc/y3VzRPHN)