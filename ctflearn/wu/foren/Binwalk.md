# Binwalk

Here is a file with another file hidden inside it. Can you extract it? https://mega.nz/#!qbpUTYiK!-deNdQJxsQS8bTSMxeUOtpEclCI-zpK7tbJiKV0tXYY

## Solution

```php
$ binwalk PurpleThing.jpeg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 780 x 720, 8-bit/color RGBA, non-interlaced
41            0x29            Zlib compressed data, best compression
153493        0x25795         PNG image, 802 x 118, 8-bit/color RGBA, non-interlaced
```

It can be seen that there are PNG files that have been inserted into the .jpeg file. We can extract it to get the image. You can use `dd` or `foremost`.

```php
$ dd if=PurpleThing.jpeg bs=1 skip=153493 of=hidden_image.png
11309+0 records in
11309+0 records out
11309 bytes (11 kB, 11 KiB) copied, 2.4054 s, 4.7 kB/s
```
or

```php
$ foremost -t png -i PurpleThing.jpeg
Processing: PurpleThing.jpeg
|*|
$ cd output
$ ls
audit.txt  png
$ cd png
```
then you will get the 2 png files, open it and get the flag.
## Flag
    ABCTF{b1nw4lk_is_us3ful}