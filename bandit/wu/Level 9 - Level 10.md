## Level Goal

The password for the next level is stored in the file data.txt in one of the few human-readable strings, preceded by several ‘=’ characters.

## Solution

Login ssh via terminal

``` 
ssh bandit.labs.overthewire.org -p 2220 -l username 
```
 
username : bandit9 <br>
password : 4CKMh1JI91bUIZZPXDqGanal4xvAg0JM

use ```ls``` to check what is in the directory, found file **data.txt**

Then, we can use the ```strings``` command because the question contains such instructions, add the ```grep``` command as well because the question begins with several "=".

    strings data.txt | grep"=="

The password that can be obtained is : ```FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey```

[![9-10.png](https://i.postimg.cc/9X8BGqCQ/9-10.png)](https://postimg.cc/c63YWCvp)