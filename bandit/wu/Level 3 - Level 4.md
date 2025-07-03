## Level Goal

The password for the next level is stored in a hidden file in the inhere directory.

## Solution

Login ssh via terminal

``` 
ssh bandit.labs.overthewire.org -p 2220 -l username 
```
 
username : bandit3 <br>
password : MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx

use ```ls``` to check what is in the directory
then open **inhere** folder using ```cd inhere``` command

then use ```ls -la``` to check what is in **inhere** folder
and found a file named **...Hiding-From-You**

use ```cat ...Hiding-From-You``` command to view the contents of the file.

and we got the password : ```2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ```

[![3-4.png](https://i.postimg.cc/qv6Xy4qS/3-4.png)](https://postimg.cc/VJ1CcyjW)