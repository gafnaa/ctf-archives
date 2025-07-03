## Level Goal

The password for the next level is stored in the file data.txt, where all lowercase (a-z) and uppercase (A-Z) letters have been rotated by 13 positions

## Solution

Login ssh via terminal

``` 
ssh bandit.labs.overthewire.org -p 2220 -l username 
```
 
username : bandit11 <br>
password : dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr

use ```ls``` to check what is in the directory, found file **data.txt**

then, do ```cat data.txt``` to view the content of the file

karena pada soal sudah diberitahu jika kode dienkripsi menggunakan metode ROT13, tinggal lakukan decrypt. Di sini saya menggunakan [CyberChef](https://gchq.github.io/CyberChef/)

The password that can be obtained is : ```7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4```

[![11-12.png](https://i.postimg.cc/d0jR6HYL/11-12.png)](https://postimg.cc/7CbTYNbk)