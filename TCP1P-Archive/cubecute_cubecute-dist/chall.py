import os
from Crypto.Util.number import getPrime, bytes_to_long

m = bytes_to_long(os.getenv("FLAG").encode())
p = getPrime(512)
n = p * p * p
e = 65537
c = pow(m, e, n)

print(f"{n,c=}")
