# My Friend John
Have you met my friend John?

He's not so scary, even though they call him "The Ripper".

## Solution

Here are my steps to solve it

```php
$ cd MyFriendJohn

$ ls
use-rockyou.zip

$ fcrackzip -v -D -p /usr/share/wordlists/rockyou.txt -u use-rockyou.zip
found file 'custom-list.txt', (size cp/uc    327/   536, flags 9, chk 8892)
found file 'custom-list.zip', (size cp/uc    454/   442, flags 9, chk 89d9)
checking pw luis99yilmar

PASSWORD FOUND!!!!: pw == kdbs0429

$ unzip use-rockyou.zip
Archive:  use-rockyou.zip
[use-rockyou.zip] custom-list.txt password:
  inflating: custom-list.txt
 extracting: custom-list.zip

$ ls
custom-list.txt  custom-list.zip  use-rockyou.zip
```

It seems that `custom-list.txt` is a special wordlist for cracking `custom-list.zip`

```php
$ fcrackzip -v -D -p custom-list.txt -u custom-list.zip
found file 'brute-force-pin.zip', (size cp/uc    238/   226, flags 9, chk 8914)


PASSWORD FOUND!!!!: pw == 1N73rD3N0M1N4710N41

$ unzip custom-list.zip
Archive:  custom-list.zip
[custom-list.zip] brute-force-pin.zip password:
 extracting: brute-force-pin.zip

$ ls
brute-force-pin.zip  custom-list.txt  custom-list.zip  use-rockyou.zip

$ fcrackzip -v -D -p /usr/share/wordlists/rockyou.txt -u brute-force-pin.zip
found file 'flag.txt', (size cp/uc     44/    32, flags 9, chk 86d2)
checking pw bb4746

PASSWORD FOUND!!!!: pw == 991337

$ unzip brute-force-pin.zip

$ cat flag.txt
```

Although in this chat we are advised to use the `john the ripper` tool, I prefer to use the `fcrackzip` tool because it is simpler.

## Flag
    CTFlearn{s0_n0W_y0uv3_M3t_J0hN}