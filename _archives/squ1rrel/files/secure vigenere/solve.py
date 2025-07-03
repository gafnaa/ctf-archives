import itertools
import string

ciphertext = "kmyiwzynttexqfztcmzipprmuxtotx"
alphabet = string.ascii_lowercase
keyspace = "squirrelctf"

common_words = ["flag", "ctf", "the", "this", "you", "have", "squirrel"]

def decrypt(ciphertext, key):
    plaintext = ""
    for i in range(len(ciphertext)):
        c = ord(ciphertext[i]) - ord('a')
        k = ord(key[i % len(key)]) - ord('a')
        p = (c - k) % 26
        plaintext += chr(p + ord('a'))
    return plaintext

def score_plaintext(pt):
    return sum(word in pt for word in common_words)

best = []

# Brute-force all keys up to a certain length
for key_len in range(1, 8):  # bisa ditambah
    for key in itertools.product(keyspace, repeat=key_len):
        key_str = ''.join(key)
        pt = decrypt(ciphertext, key_str)
        score = score_plaintext(pt)
        if score >= 2:  # cukup banyak kata match
            best.append((score, key_str, pt))

# Urutkan dan tampilkan yang paling bagus
best.sort(reverse=True)
for score, key, pt in best[:10]:
    print(f"[+] Key: {key} | Score: {score} | PT: {pt}")
