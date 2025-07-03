# abandoned place

the flag is outside of the pic, try to find it. another hint: dimensions, dimensions, everything is in dimensions.

## Solution

hint: dimensions

```
$ exiftool abondoned_street_challenge2.jpg
ExifTool Version Number         : 13.10
File Name                       : abondoned_street_challenge2.jpg
Directory                       : .
File Size                       : 1009 kB
File Modification Date/Time     : 2025:04:02 20:07:20+07:00
File Access Date/Time           : 2025:04:02 20:30:23+07:00
File Inode Change Date/Time     : 2025:04:02 20:07:33+07:00
File Permissions                : -rwxrwxrwx
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : inches
X Resolution                    : 314
Y Resolution                    : 314
Image Width                     : 2016
Image Height                    : 900
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 2016x900
Megapixels                      : 1.8
```

```
image size : 2016 x 900
```

```py
$ python3
Python 3.13.2 (main, Feb  5 2025, 01:23:35) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(2016)
'0x7e0'
>>> hex(900)
'0x384'
```

open HxD
search hex `0384` edit to `07e0` then save it.
Open the image again, you will see the flag

## Flag
    CTF{urban_exploration}