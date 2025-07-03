# Wasiat

## Desc

## Solution

Dikasi file .zip. setelah dibuka pakai winrar ternyata ada file `flag.txt`.
Tapi ketika dibuka ternyata disuruh untuk memasukkan password zip nya.

Kita tinggal crack password tersebut:

```
fcrackzip -v -D -p /usr/share/wordlists/rockyou.txt -u wasiat.zip
found file 'flag.txt', (size cp/uc     36/    24, flags 9, chk 5d65)


PASSWORD FOUND!!!!: pw == 123qwe
```

Tinggal ekstrak zip nya menggunakan password tersebut

Terakhir tinggal buka file `flag.txt`

## Flag
    IFEST13{CR4CK_P4SSW0RD}
