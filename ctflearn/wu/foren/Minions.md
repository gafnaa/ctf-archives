# Minions 

Hey! Minions have stolen my flag, encoded it few times in one cipher, and then hidden it somewhere there: https://mega.nz/file/1UBViYgD#kjKISs9pUB4E-1d79166FeX3TiY5VQcHJ_GrcMbaLhg Can you help me? TIP: Decode the flag until you got a sentence.

## Solution
Download the image first

```
$ binwalk Hey_You.png

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 1144 x 1056, 8-bit/color RGBA, non-interlaced
91            0x5B            Zlib compressed data, compressed
868059        0xD3EDB         RAR archive data, version 5.x
```

There seems to be a hidden .rar file inside, extract it using the following command

```
$ binwalk -e Hey_You.png
```

```php
$ ls -la
total 856
drwxrwxrwx 1 gafnaa gafnaa    512 Apr  2 18:53 .
drwxrwxrwx 1 gafnaa gafnaa    512 Apr  2 18:55 ..
-rwxrwxrwx 1 gafnaa gafnaa      0 Apr  2 18:53 5B
-rwxrwxrwx 1 gafnaa gafnaa 869337 Apr  2 18:53 5B.zlib
drwxrwxrwx 1 gafnaa gafnaa    512 Apr  2 18:53 D3EDB
-rwxrwxrwx 1 gafnaa gafnaa   1369 Apr  2 18:53 D3EDB.rar
-rwxrwxrwx 1 gafnaa gafnaa     73 Jun 23  2020 ..txt

$ cat ..txt
https://mega.nz/file/wZw2nAhS#i3Q0r-R8psiB8zwUrqHTr661d8FiAS1Ott8badDnZko
```

then, open link and download the file.
![only](/ctflearn/files/Only_Few_Steps.jpg)


```
$ binwalk Only_Few_Steps.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
30            0x1E            TIFF image data, little-endian offset of first image directory: 8
426           0x1AA           Copyright string: "Copyright (c) 1998 Hewlett-Packard Company"
141318        0x22806         RAR archive data, version 5.x
```
There seems to be a hidden .rar file and images inside, extract it using the following command

```
$ binwalk -e Only_Few_Steps.jpg
```
then do `ls` to look inside the folder.
```
$ ls -la
total 392
drwxrwxrwx 1 gafnaa gafnaa    512 Apr  2 18:55  .
drwxrwxrwx 1 gafnaa gafnaa    512 Apr  2 18:55  ..
-rwxrwxrwx 1 gafnaa gafnaa 194041 Apr  2 18:55  22806.rar
-rwxrwxrwx 1 gafnaa gafnaa 204228 Jun 23  2020 'YouWon(Almost).jpg'
```

```php
$ strings YouWon\(Almost\).jpg | grep "CTF"
CTF{VmtaU1IxUXhUbFZSYXpsV1RWUnNRMVpYZEZkYWJFWTJVVmhrVlZGVU1Eaz0=)

$ echo "VmtaU1IxUXhUbFZSYXpsV1RWUnNRMVpYZEZkYWJFWTJVVmhrVlZGVU1Eaz0=" | base64 -d
VkZSR1QxTlVRazlWTVRsQ1ZXdFdabEY2UVhkVVFUMDk=

$ echo "VkZSR1QxTlVRazlWTVRsQ1ZXdFdabEY2UVhkVVFUMDk=" | base64 -d
VFRGT1NUQk9VMTlCVWtWZlF6QXdUQT09

$ echo "VFRGT1NUQk9VMTlCVWtWZlF6QXdUQT09" | base64 -d
TTFOSTBOU19BUkVfQzAwTA==

$ echo "TTFOSTBOU19BUkVfQzAwTA=="| base64 -d
M1NI0NS_ARE_C00L
```

## Flag
    CTF{M1NI0NS_ARE_C00L}

