from Crypto.Util.number import *

flag = bytes_to_long(b"RAMADAN{testing}")
p, q = getPrime(1024), getPrime(1024)
pq = p * q
e = 3

c = pow(flag, e , pq)
print(f"{pq = }")
print(f"{c = }")
