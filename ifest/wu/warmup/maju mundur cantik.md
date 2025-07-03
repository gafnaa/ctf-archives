# Maju Mundur Cantik

## Desc

## Solution

Diberikan file `csr.txt` yang isinya yaitu:

```
> cat csr.txt
SPOCD13{M4OC4B_M1ZR3B}
```

Sepertinya itu flag nya tapi di enkripsi menggunakan suatu metode cipher.
Coba kita gunakan Cipher Identifier untuk mencari kemungkinan metode ciphernya.
https://www.dcode.fr/cipher-identifier


Didapat hasil kalo kemungkinan paling tinggi yaitu **ROT Cipher**

Lalu, tinggal decode dan dapat flagnya!

https://www.dcode.fr/rot-cipher

## Flag

    IFEST13{C4ES4R_C1PH3R}