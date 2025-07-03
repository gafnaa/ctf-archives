## Level Goal

The password for the next level is stored in the file data.txt next to the word millionth

## Solution

Login ssh via terminal

``` 
ssh bandit.labs.overthewire.org -p 2220 -l username 
```
 
username : bandit7 <br>
password : morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj

use ```ls``` to check what is in the directory, found file **data.txt**, after that using ```grep``` command with additional parameters to find the password. 

We can use this command

    grep "millionth" data.txt

The password that can be obtained is : ```dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc```

[![7-8.png](https://i.postimg.cc/Hsbk0xqk/7-8.png)](https://postimg.cc/Ln6S2H4c)