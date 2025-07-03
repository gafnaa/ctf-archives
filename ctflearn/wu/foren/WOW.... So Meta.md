# WOW.... So Meta
This photo was taken by our target. See what you can find out about him from it. https://mega.nz/#!ifA2QAwQ!WF-S-MtWHugj8lx1QanGG7V91R-S1ng7dDRSV25iFbk
## Solution

```cs
$ exiftool meta.jpg
ExifTool Version Number         : 13.10
File Name                       : meta.jpg
Directory                       : .
File Size                       : 104 kB
File Modification Date/Time     : 2025:03:31 19:08:04+07:00
File Access Date/Time           : 2025:03:31 19:08:29+07:00
File Inode Change Date/Time     : 2025:03:31 19:08:29+07:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Current IPTC Digest             : dbad0204d16a63027791298bc460859a
Coded Character Set             : UTF8
Application Record Version      : 2
Digital Creation Time           : 16:45:55
Digital Creation Date           : 2014:12:27
Time Created                    : 16:45:55
IPTC Digest                     : dbad0204d16a63027791298bc460859a
Exif Byte Order                 : Big-endian (Motorola, MM)
Orientation                     : Horizontal (normal)
X Resolution                    : 72
Y Resolution                    : 72
Resolution Unit                 : inches
Software                        : Photos 1.5
Modify Date                     : 2014:12:27 16:45:55
Exif Version                    : 0221
Date/Time Original              : 2014:12:27 16:45:55
Create Date                     : 2014:12:27 16:45:55
Components Configuration        : Y, Cb, Cr, -
Light Source                    : Tungsten (Incandescent)
Flashpix Version                : 0100
Color Space                     : sRGB
Exif Image Width                : 4002
Exif Image Height               : 1536
Scene Capture Type              : Standard
Sharpness                       : Hard
Padding                         : (Binary data 2060 bytes, use -b option to extract)
XMP Toolkit                     : XMP Core 5.4.0
Creator Tool                    : Photos 1.5
Date Created                    : 2014:12:27 16:45:55
Warning                         : [minor] Fixed incorrect URI for xmlns:MicrosoftPhoto
Camera Serial Number            : flag{EEe_x_I_FFf}
Image Width                     : 800
Image Height                    : 307
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 800x307
Megapixels                      : 0.246
Date/Time Created               : 2014:12:27 16:45:55
Digital Creation Date/Time      : 2014:12:27 16:45:55

$ exiftool -b meta.jpg
Warning: [minor] Fixed incorrect URI for xmlns:MicrosoftPhoto - meta.jpg
13.10meta.jpg.1038082025:03:31 19:08:04+07:002025:03:31 19:09:05+07:002025:03:31 19:08:29+07:00100644JPEGJPGimage/jpeg1 1dbad0204d16a63027791298bc460859a216:45:552014:12:2716:45:55dbad0204d16a63027791298bc460859aMM172722Photos 1.52014:12:27 16:45:5502212014:12:27 16:45:552014:12:27 16:45:551 2 3 03010014002153602XMP Core 5.4.0Photos 1.52014:12:27 16:45:55[minor] Fixed incorrect URI for xmlns:MicrosoftPhotoflag{EEe_x_I_FFf}8003070832 2800 3070.24562014:12:27 16:45:552014:12:27 16:45:55
```

## Flag
    CTFlearn{EEe_x_I_FFf}