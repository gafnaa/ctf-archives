## Level Goal

The password for the next level is stored in a file called - located in the home directory

## Solution

Login ssh via terminal

``` 
ssh bandit.labs.overthewire.org -p 2220 -l username 
```

username : bandit1 <br>
password : ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5I 

type ``` ls -la ``` to check all files in directory, after found **-** file, just using ```cat ./-``` command to view the contents of the file.

and we got the password : ```263JGJPfgU6LtdEvgfWU1XP5yac29mFx```

[![1-2.png](https://i.postimg.cc/Pf1gznpL/1-2.png)](https://postimg.cc/vDH2bjvM)