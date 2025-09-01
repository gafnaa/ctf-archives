
import sys
from hashlib import sha256

P = 112100829556962061444927618073086278041158621998950683631735636667566868795947
EXPONENT = 3

def split(x):
    return x // P, x % P

def merge(chunk1, chunk2):
    return chunk1 * P + chunk2

def ff(x):
    return ((x * EXPONENT) * 0x5DEECE66D) % P

def gg(x):
    digest = sha256(int(x).to_bytes(256, "big")).digest()
    return int.from_bytes(digest, "big") % P

def transform(x, y, i, CONSTANT):
    u = x
    if i % 11 == 0:
        v = (y + ff(u)) % P
    else:
        v = (y + gg(u)) % P
    v = (v + CONSTANT[i]) % P
    return v, u

def inv_transform(v, u, i, CONSTANT):
    if i % 11 == 0:
        y = (v - CONSTANT[i] - ff(u)) % P
    else:
        y = (v - CONSTANT[i] - gg(u)) % P
    return u, y

def decrypt(ciphertext, ROUNDS, CONSTANT):
    chunk1, chunk2 = split(ciphertext)
    for i in reversed(range(ROUNDS)):
        if i % 5 == 0:
            chunk1, chunk2 = inv_transform(chunk1, chunk2, i, CONSTANT)
        else:
            chunk2, chunk1 = inv_transform(chunk2, chunk1, i, CONSTANT)
    return merge(chunk1, chunk2)

if __name__ == "__main__":
    with open("out.txt") as f:
        ciphertext = int(f.read().strip(), 16)

    for rounds in range(26, 54):  # brute possible ROUNDS
        CONSTANT = [(44 * i ^ 3 + 98 * i ^ 2 + 172 * i + 491) % P for i in range(rounds)]
        try:
            plaintext_int = decrypt(ciphertext, rounds, CONSTANT)
            flag = plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, "big")
            if b"snake" in flag.lower():  # heuristic: flag usually inside
                print(f"[+] Found with ROUNDS={rounds}: {flag}")
        except Exception as e:
            continue
