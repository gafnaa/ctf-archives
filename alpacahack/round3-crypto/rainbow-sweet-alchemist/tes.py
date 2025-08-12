import random
from math import prod, gcd
from Crypto.Util.number import isPrime, long_to_bytes, inverse

flag = b'\x04\xe2\x8d\x10\x98q\x17'

print("🚩 Flag:", flag.decode())