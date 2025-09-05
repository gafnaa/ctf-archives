from Crypto.Cipher import AES
from Crypto.Util import number
from sympy import factorint
from math import gcd
from functools import reduce

# ======================
# Helper Carmichael λ(n)
# ======================
def carmichael_lambda(n):
    factors = factorint(n)  # <-- pakai sympy sekarang
    lams = []
    for p, k in factors.items():
        if p == 2 and k >= 3:
            lam = 2**(k-2)
        else:
            lam = (p-1) * (p**(k-1))
        lams.append(lam)
    return reduce(lambda a, b: a * b // gcd(a, b), lams)

# ======================
# Data
# ======================
n = 107502945843251244337535082460697583639357473016005252008262865481138355040617
cipher_hex = "b6c4d050dd08fd8471ef06e73d39b359e3fc370ca78a3426f01540985b88ba66ec9521e9b68821fed1fa625e11315bf9"
cipher = bytes.fromhex(cipher_hex)

primes = [p for p in range(100) if number.isPrime(p)]

# ======================
# Build tower mod λ(n)
# ======================
lam = carmichael_lambda(n)
exp = 1
for p in reversed(primes):
    exp = pow(p, exp, lam)

int_key = pow(primes[0], exp, n)
int_key = int(int_key % n)   # convert ke Python int
key = int_key.to_bytes(32, byteorder="big")

# ======================
# Decrypt
# ======================
aes = AES.new(key, AES.MODE_ECB)
plain_bytes = aes.decrypt(cipher)

print("Raw decrypted:", plain_bytes)
print("Flag:", plain_bytes.decode(errors="ignore").rstrip("_"))
