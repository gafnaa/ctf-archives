## Level Goal

The password for the next level is stored in a file called spaces in this filename located in the home directory

## Solution

Login ssh via terminal

``` 
ssh bandit.labs.overthewire.org -p 2220 -l username 
```

username : bandit2 <br>
password : 263JGJPfgU6LtdEvgfWU1XP5yac29mFx 

do ``` ls -la``` command, to checking **spaces in this filename** file is availabe on that directory or not. 

then use ```cat spaces\ in \ this\ filename``` command to view the contents of the file.

and we got the password : ```MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx```

[![2-3.png](https://i.postimg.cc/g221WwMR/2-3.png)](https://postimg.cc/zV4xwfYX)