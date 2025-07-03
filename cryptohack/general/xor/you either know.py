from pwn import xor

cipher_hex = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
cipher_bytes = bytes.fromhex(cipher_hex)

known_plaintext = b"crypto{"
key_start = xor(cipher_bytes[:len(known_plaintext)], known_plaintext)
print(f"Recovered key start: {key_start}")

# Kita asumsikan key-nya adalah pengulangan dari ini
# Kalau hasil decode masih aneh, kita bisa coba cari panjang key yang sebenarnya
full_key = key_start * (len(cipher_bytes) // len(key_start)) + key_start[:len(cipher_bytes) % len(key_start)]

decrypted = xor(cipher_bytes, full_key)
print(f"Decrypted: {decrypted.decode()}")
