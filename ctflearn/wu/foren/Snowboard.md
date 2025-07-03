# Snowboard 

Find the flag in the jpeg file. Good Luck!

## Solution

```php
$ file Snowboard.jpg
Snowboard.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 300x300, segment length 16, comment: "CTFlearn{CTFIsEasy!!!}", comment: "Q1RGbGVhcm57U2tpQmFuZmZ9Cg==", Exif Standard: [TIFF image data, little-endian, direntries=8, manufacturer=Canon, model=Canon EOS 6D Mark II, xresolution=138, yresolution=146, resolutionunit=2, software=GIMP 2.10.6, datetime=2019:05:07 14:37:21], progressive, precision 8, 1200x800, components 3

$ echo "Q1RGbGVhcm57U2tpQmFuZmZ9Cg==" | base64 -d
```

## Flag
    CTFlearn{SkiBanff}