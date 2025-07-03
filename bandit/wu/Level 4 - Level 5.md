## Level Goal

The password for the next level is stored in the only human-readable file in the inhere directory. Tip: if your terminal is messed up, try the “reset” command.

## Solution

Login ssh via terminal

``` 
ssh bandit.labs.overthewire.org -p 2220 -l username 
```
 
username : bandit4 <br>
password : 2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ

use ```ls -la``` to check what is in the directory
then open **inhere** folder using ```cd inhere``` command

then use ```ls -la``` to check what is in **inhere** folder,
and found some files inside the folder. To check which files are human-readable, run ```files ./*``` command. Found the file that we are looking for (-file07).

And we got the password : ```4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw```

[![4-5.png](https://i.postimg.cc/6q4xVRFY/4-5.png)](https://postimg.cc/JH8FMyrk)