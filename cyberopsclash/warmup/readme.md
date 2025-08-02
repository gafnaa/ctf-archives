# Prev

Sistem ini mempercayaimu sebagai tamu biasa, tapi kepercayaan itu bisa dimanipulasi. Cari tahu apa yang salah dan naikkan level aksesmu.

http://157.230.243.4:2930

## Solusi

ganti cookies doang

Flag : `Meta4Sec{CHALL_WARM_UP_AJA}`

# IBO

Buffer Overflow

nc 157.230.243.4 9901

## Solusi

sesuai nama chall, simple bo

```
$ nc 157.230.243.4 9901
-------------------------------
Your balance: $100

What would you like to buy?
1. Red Potion ($10)
2. Green Potion ($15)
3. Blue Potion ($20)
4. Yellow Potion ($25)
5. Black Potion ($10000)
Answer: 5

How many?
Answer: 99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999

Total Cost: $-10000
FLAG: Meta4Sec{Vuln_Integer_Buffer_Overflow}
```
Flag: `Meta4Sec{Vuln_Integer_Buffer_Overflow}`

# EaCry

Bantu saya mendapatkan flagnya : jb3xSn4OZfcz7rHoMQFJoetQM85N

## Solusi

Tinggal decode doang bang bas62

Flag : `Meta4sec{Easy_Crypto}`

# EaDf

Bantu saya dapatkan flagnya

## Solusi

Dikasi file pdf. tapi di password
tinggal crack doang si

```
$ pdfcrack -f eapdf.pdf -w /usr/share/wordlists/rockyou.txt
PDF version 1.7
Security Handler: Standard
V: 2
R: 3
P: -1060
Length: 128
Encrypted Metadata: True
FileID: 0df92f0f6711ff49ab74419fb0f9bc68
U: fb91a07be9095a5e90ee359837ca42ef00000000000000000000000000000000
O: b1fbbe9bc45938f85e0c5794a1de66426a9283337672b64cdfefc14b6b4cd1b5
found user-password: 'lancelot'
```

convert ke word, cari flag. Done!

Flag : `Meta4Sec{Easy_F0r3ns1c}`
