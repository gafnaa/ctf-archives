# Exif

If only the password were in the image?

https://mega.nz/#!SDpF0aYC!fkkhBJuBBtBKGsLTDiF2NuLihP2WRd97Iynd3PhWqRw You could really ‘own’ it with exif.

## Solution

```php
─$ exiftool exif.jpg
ExifTool Version Number         : 13.10
File Name                       : exif.jpg
Directory                       : .
File Size                       : 55 kB
File Modification Date/Time     : 2025:03:31 20:47:03+07:00
File Access Date/Time           : 2025:03:31 20:47:03+07:00
File Inode Change Date/Time     : 2025:03:31 20:47:03+07:00
File Permissions                : -rwxrwxrwx
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.02
X Resolution                    : 100
Y Resolution                    : 100
Exif Byte Order                 : Big-endian (Motorola, MM)
Resolution Unit                 : None
Y Cb Cr Positioning             : Centered
Exif Version                    : 0231
Components Configuration        : Y, Cb, Cr, -
Flashpix Version                : 0100
Owner Name                      : flag{3l1t3_3x1f_4uth0r1ty_dud3br0}
GPS Latitude Ref                : South
GPS Longitude Ref               : East
Quality                         : 60%
DCT Encode Version              : 100
APP14 Flags 0                   : [14], Encoded with Blend=1 downsampling
APP14 Flags 1                   : (none)
Color Transform                 : YCbCr
Image Width                     : 660
Image Height                    : 371
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 660x371
Megapixels                      : 0.245
GPS Latitude                    : 77 deg 17' 2.62" S
GPS Longitude                   : 44 deg 4' 7.30" E
GPS Position                    : 77 deg 17' 2.62" S, 44 deg 4' 7.30" E
```
## Flag
    flag{3l1t3_3x1f_4uth0r1ty_dud3br0}