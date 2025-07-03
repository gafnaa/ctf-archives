import binascii

# Ciphertext yang diberikan
hex_cipher = "434542034a46505a4c516a6a5e496b5b025b5f6a46760a0c420342506846085b6a035f084b616c5f66685f616b535a035f6641035f6b7b5d765348"
cipher_bytes = bytes.fromhex(hex_cipher)

# Diketahui plaintext awal
plaintext_start = b"squ1rrel{"

# Ambil 9 byte pertama dari ciphertext
cipher_start = cipher_bytes[:len(plaintext_start)]

# XOR untuk cari key
key = bytearray()
for c, p in zip(cipher_start, plaintext_start):
    key.append(c ^ p)

# Tampilkan hasil key awal
print("[*] Key awal (9 byte pertama):", list(key))  # dalam bentuk angka
print("[*] Key awal (as string):", ''.join([chr(b) if 32 <= b <= 126 else '.' for b in key]))

# Gunakan key ini (sementara) untuk dekripsi
key_len = 13
# Isi 4 byte sisanya dengan 0x00 untuk sementara (placeholder)
while len(key) < key_len:
    key.append(0)

# Lakukan dekripsi pakai key sementara
plaintext = bytearray()
for i in range(len(cipher_bytes)):
    k = key[i % key_len]
    p = cipher_bytes[i] ^ k
    plaintext.append(p)

# Tampilkan hasil dekripsi sementara
print("\n[*] Plaintext (sementara):")
print(plaintext.decode(errors='ignore'))
