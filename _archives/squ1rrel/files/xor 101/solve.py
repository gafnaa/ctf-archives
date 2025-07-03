# Langkah 1: Dapatkan 9 byte pertama dari ciphertext dan xor dengan 'squ1rrel{'
cipher_hex = "434542034a46505a4c516a6a5e496b5b025b5f6a46760a0c420342506846085b6a035f084b616c5f66685f616b535a035f6641035f6b7b5d765348"
cipher_bytes = bytes.fromhex(cipher_hex)

# Diketahui plaintext diawali dengan:
known_prefix = b"squ1rrel{"

# Hitung 9 byte pertama dari key
key_start = [c ^ p for c, p in zip(cipher_bytes, known_prefix)]

# Panjang key total
key_len = 13

# Valid karakter dalam flag
import string
valid_chars = set(string.ascii_letters + string.digits + "_{}")

# Brute-force 4 byte terakhir (dari 32 sampai 126 saja agar printable dan realistis)
from itertools import product

results = []

for tail in product(range(32, 127), repeat=4):  # printable ASCII
    full_key = key_start + list(tail)
    plaintext = bytearray()
    for i in range(len(cipher_bytes)):
        k = full_key[i % key_len]
        p = cipher_bytes[i] ^ k
        plaintext.append(p)
    try:
        decoded = plaintext.decode()
        if decoded.startswith("squ1rrel{") and decoded.endswith("}") and set(decoded).issubset(valid_chars):
            results.append(("".join(chr(c) for c in full_key), decoded))
            break
    except:
        continue

results
