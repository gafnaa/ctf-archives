import os
from Crypto.Util.number import bytes_to_long, getRandomNBitInteger, isPrime, getPrime

def nextPrime(n):
    while not isPrime(n := n + 1):
        continue
    return n

def gen():
    attempts = 0
    max_attempts = 1000
    while attempts < max_attempts:
        q = getPrime(128)
        r = getRandomNBitInteger(128)
        p = q * nextPrime(r) + nextPrime(q) * r
        if p.bit_length() <= 256 and isPrime(p) and isPrime(q):
            return p, q, r
        attempts += 1

    raise ValueError("Failed to generate primes within attempts")

flag = b"TCP1P{testing}"
m = bytes_to_long(flag)
p, q, r = gen()
n = p * q
phi = (p - 1) * (q - 1)
e = 0x10001
d = pow(e, -1, phi)
c = pow(m, e, n)
print(f"{n=}")
print(f"{e=}")
print(f"{c=}")
print(f"{r=}")
