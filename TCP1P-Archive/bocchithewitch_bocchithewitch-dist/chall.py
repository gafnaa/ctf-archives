from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from libnum import n2s
import random
import secrets
import signal

signal.alarm(180)
flag = open('flag.txt', 'r').read()
key = RSA.generate(2048, random.randbytes)
cipher = PKCS1_OAEP.new(key)
s = secrets.randbelow(key.u)
de = pow(key.e, -1, key.d)
mask = int(input("mask?> "))
if mask.bit_count() > 300:
    print("No")
    exit(1)
print(f"N: {key.n}")
print(f"Hint: {de & mask}")
for i in range(10):
    msg = n2s(s + i)
    print(f"ct_{i}: {cipher.encrypt(msg).hex()}")
guess = int(input("guess?> "))
if guess == s:
    print(flag)
else: print("Meh")