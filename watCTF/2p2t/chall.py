from Crypto.Util.number import getPrime, isPrime, bytes_to_long

def nextPrime(k):
    while not isPrime(k):
        k += 1
    return k

p = getPrime(512)
q = nextPrime(2*p)

N = p*q
e = 65537
pt = bytes_to_long(open('flag.txt', 'rb').read())
ct = pow(pt, e, N)

print(f'N = {N}')
print(f'e = {e}')
print(f'ct = {ct}')
