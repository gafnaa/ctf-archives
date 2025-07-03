## Level Goal

The password for the next level is stored in the file data.txt and is the only line of text that occurs only once

## Solution

Login ssh via terminal

``` 
ssh bandit.labs.overthewire.org -p 2220 -l username 
```
 
username : bandit8 <br>
password : dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc

use ```ls``` to check what is in the directory, found file **data.txt**


Then, we can use   ```sort``` command to filtering text that occurs only once, here the command

    sort data.txt | uniq -u

The password that can be obtained is : ```4CKMh1JI91bUIZZPXDqGanal4xvAg0JM```

[![8-9.png](https://i.postimg.cc/sDT0N9d6/8-9.png)](https://postimg.cc/F7JZfSK3)