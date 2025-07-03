encrypted = "┠ସ弌ⴑᤎ܀᤼जఫ଑Љማ"
key = "crypto"

# Konversi ke bytes
encrypted_bytes = encrypted.encode("utf-16-le")  # karakter Unicode

# Ulangi key agar sepanjang encrypted_bytes
key_bytes = (key * (len(encrypted_bytes) // len(key) + 1)).encode("utf-8")[:len(encrypted_bytes)]

# XOR byte-by-byte
decrypted_bytes = bytes([b ^ k for b, k in zip(encrypted_bytes, key_bytes)])

# Coba decode
try:
    decrypted_text = decrypted_bytes.decode("utf-8")
except UnicodeDecodeError:
    decrypted_text = decrypted_bytes.decode("latin1")  # cadangan

print(decrypted_text)
