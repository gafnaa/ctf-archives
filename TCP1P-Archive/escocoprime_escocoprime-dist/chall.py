from Crypto.Util.number import *
import random
from datetime import datetime

flag = bytes_to_long(b"RAMADAN{testing}")

def generatepub():
        a, b = 0, 0
        while GCD(a,b) != 1:
                random.seed(int(datetime.now().timestamp()))
                a = random.randint(128, 65536)
                b = random.randint(128, 65536)
        return a, b

p, q = getPrime(1024), getPrime(1024)
pq = p * q

a, b = generatepub()

msg1 = pow(flag, a, pq)
msg2 = pow(flag, b, pq)

print(f"{pq = }")
print(f"{a = }")
print(f"{b = }")
print(f"{msg1 = }")
print(f"{msg2 = }")
