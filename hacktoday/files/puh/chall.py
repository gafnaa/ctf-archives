from Crypto.Util.number import getPrime

FLAG = open('flag.txt').read()

wordlist = ["puh", "ajarin", "sepuh", "aku", "dong", "mega", "pro", "legend", "top", "noob", "dewa"]

def int_to_words(n):
    base = 11
    digits = []
    while n > 0:
        digits.append(n % base)
        n //= base
    while len(digits) < 6:
        digits.append(0)
    return [wordlist[d] for d in reversed(digits)]

def encrypt(flag):
    while len(flag) % 4 != 0:
        flag += b'_'
    
    primes = []
    while len(primes) < 3:
        p = getPrime(20)
        if p not in primes:
            primes.append(p)

    ciphertext = []

    for i in range(0, len(flag), 4):
        chunk = flag[i:i+4]
        x = int.from_bytes(chunk, 'big')
        residues = [x % p for p in primes]
        for r in residues:
            ciphertext.extend(int_to_words(r))
    
    return ciphertext, primes

def main():
    ciphertext, primes = encrypt(FLAG)

    with open("cipher.txt", "w") as f:
        f.write(' '.join(ciphertext))

    with open("primes.txt", "w") as f:
        f.write('\n'.join(str(p) for p in primes))

if __name__ == "__main__" :
    main()