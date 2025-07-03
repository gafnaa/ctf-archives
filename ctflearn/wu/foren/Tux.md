# Tux

The flag is hidden inside the Penguin! Solve this challenge before solving my 100 point Scope challenge which uses similar techniques as this one.

## Solution

```
$ file Tux.jpg
Tux.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, comment: "ICAgICAgUGFzc3dvcmQ6IExpbnV4MTIzNDUK", baseline, precision 8, 196x216, components 3
```

```
$ echo "ICAgICAgUGFzc3dvcmQ6IExpbnV4MTIzNDUK" | base64 -d
      Password: Linux12345
```

```
$ binwalk Tux.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             JPEG image data, JFIF standard 1.01
5488          0x1570          Zip archive data, encrypted at least v1.0 to extract, compressed size: 39, uncompressed size: 27, name: flag
5679          0x162F          End of Zip archive, footer length: 22
```

```
$ binwalk -e Tux.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------

WARNING: Extractor.execute failed to run external extractor 'jar xvf '%e'': [Errno 2] No such file or directory: 'jar', 'jar xvf '%e'' might not be installed correctly
5488          0x1570          Zip archive data, encrypted at least v1.0 to extract, compressed size: 39, uncompressed size: 27, name: flag

WARNING: One or more files failed to extract: either no utility was found or it's unimplemented
```

```
$ cd _Tux.jpg.extracted/
``` 

then, open the zip file. Input the password and open the flag!

## Flag
    CTFlearn{Linux_Is_Awesome}
