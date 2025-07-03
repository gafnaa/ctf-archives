cipher_bytes = bytes.fromhex("434542034a46505a4c516a6a5e496b5b025b5f6a46760a0c420342506846085b6a035f084b616c5f66685f616b535a035f6641035f6b7b5d765348")

key = [48, 52, 55, 50, 56, 52, 53, 54, 55, 95, 108, 111, 108]  # dari hasil brute-force

key_len = 13
plaintext = bytearray()
for i in range(len(cipher_bytes)):
    k = key[i % key_len]
    p = cipher_bytes[i] ^ k
    plaintext.append(p)

# Print hasil
print(plaintext.decode())
