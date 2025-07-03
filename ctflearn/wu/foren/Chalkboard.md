# Chalboard

Solve the equations embedded in the jpeg to find the flag. Solve this problem before solving my Scope challenge which is worth 100 points.

## Solution

do `exiftool` and you will get the hint
```
$ exiftool math.jpg
ExifTool Version Number         : 13.10
File Name                       : math.jpg
Directory                       : .
File Size                       : 191 kB
File Modification Date/Time     : 2025:04:01 19:42:47+07:00
File Access Date/Time           : 2025:04:01 19:42:47+07:00
File Inode Change Date/Time     : 2025:04:01 19:42:47+07:00
File Permissions                : -rwxrwxrwx
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Comment                         : The flag for this challenge is of the form:..CTFlearn{I_Like_Math_x_y}..where x and y are the solution to these equations:..3x + 5y = 31..7x + 9y = 59...
Image Width                     : 640
Image Height                    : 316
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 640x316
Megapixels                      : 0.202
```

just find the solution for `x` and `y`. 
```
x = 2
y = 5
```
## Flag
    CTFlearn{I_Like_Math_2_5}