def letter_to_num(c):
    return ord(c.upper()) - ord('A')

def num_to_letter(n):
    return chr((n % 26) + ord('A'))

def decrypt_otp(ciphertext, key):
    decrypted = ""
    for i in range(len(ciphertext)):
        c = letter_to_num(ciphertext[i])
        k = letter_to_num(key[i % len(key)])
        p = (c - k + 26) % 26
        decrypted += num_to_letter(p)
    return decrypted

# Daftar common passwords yang panjangnya sama dengan ciphertext (7 huruf)
common_keys = [
    "password", "123456", "qwerty", "letmein", "iloveyou", "admin", 
    "welcome", "monkey", "abc123", "sunshine", "princess", "123123", 
    "welcome1", "trustno1", "football", "qwerty123", "1q2w3e4r", "dragon", 
    "master", "hello123", "starwars"
]

ciphertext = "GWOFZPT"

for key in common_keys:
    if len(key) == len(ciphertext):
        plaintext = decrypt_otp(ciphertext, key)
        print(f"Key: {key} -> Plaintext: {plaintext}")
