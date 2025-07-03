## Level Goal

The password for the next level is stored in the file data.txt, which contains base64 encoded data

## Solution

Login ssh via terminal

``` 
ssh bandit.labs.overthewire.org -p 2220 -l username 
```
 
username : bandit10 <br>
password : FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey

use ```ls``` to check what is in the directory, found file **data.txt**

then, do ```cat data.txt``` to view the content of the file

then, use this command to convert the password

    echo" (your base64 text) " | base64 --decode

The password that can be obtained is : ```dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr```

[![10-11.png](https://i.postimg.cc/pdFYjW0Y/10-11.png)](https://postimg.cc/rdqrXk2K)