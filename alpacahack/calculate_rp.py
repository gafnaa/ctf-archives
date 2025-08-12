from Crypto.Util.number import isPrime
import gmpy2

def nextPrime(n):
    n = gmpy2.mpz(n)
    while True:
        n += 1
        if gmpy2.is_prime(n):
            return n

r = gmpy2.mpz(96744653319697623891339120544643953453203088163395284702234565865708056065564)
r_p = nextPrime(r)
print(f"r_p = {r_p}")
