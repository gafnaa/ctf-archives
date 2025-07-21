import hashlib
from Crypto.Cipher import AES
import sys

# Data from out.txt
given_key_hash_hex = "3d9977528e9d2ce5"
given_enc_hex = "7d9606e6dcf2f6d441e5e1efd9eb91afc32db2dc233cc1978eb090173eec1de81a5c7bd7a7f3358d35c781dd5cb64d69"

# Convert hex to bytes
given_enc_bytes = bytes.fromhex(given_enc_hex)

# The original plaintext length is 16 bytes (AES block size)
# "ACE{***********}" is 16 characters long.
# AES.MODE_ECB does not use padding by default, so the plaintext must be a multiple of 16 bytes.
# The flag format "ACE{...}" suggests it's a fixed length.
# Let's assume the original plaintext was 16 bytes.
# The encrypted output is 32 bytes, which means the original plaintext was 32 bytes.
# "ACE{***********}" is 16 bytes. The output is 32 bytes. This means the plaintext was padded or it's two blocks.
# Let's re-check the chall.py: enc = AES.new(hashlib.sha256(key).digest(), AES.MODE_ECB).encrypt("ACE{***********}")
# The string "ACE{***********}" is 16 characters long.
# If the output is 32 bytes, it means the plaintext was effectively 32 bytes.
# This implies that the string "ACE{***********}" was padded to 32 bytes before encryption.
# AES.new in pycryptodome with MODE_ECB does not automatically pad.
# However, the original chall.py uses Crypto.Cipher.AES, which might behave differently or the string was implicitly padded.
# Let's assume the plaintext was "ACE{***********}" + some padding to make it 32 bytes.
# Or, more likely, the flag is longer than 16 bytes and the example "ACE{***********}" is just a placeholder.
# The length of the encrypted text is 32 bytes, which means the plaintext was 32 bytes.
# Let's assume the flag is 32 bytes long.

# Brute-force 7-byte key
# The key is 7 bytes, so 256^7 possibilities. This is 2^56, which is feasible.
# 2^56 = 7.2 * 10^16. This will take a very long time if done naively.
# However, the hash function used is Python's built-in hash(), not a cryptographic hash.
# Python's hash() function is not guaranteed to be consistent across different runs or Python versions.
# But in a CTF, it's usually consistent within the challenge environment.
# The hash() of a string is an integer. hex(hash(key))[2:] converts it to hex string.

# Let's try to brute force the 7-byte key.
# The key is `bytes` type.
# The hash function is `hash(key)`.

print("Starting brute-force...")
found_key = None
for b1 in range(256):
    for b2 in range(256):
        for b3 in range(256):
            for b4 in range(256):
                for b5 in range(256):
                    for b6 in range(256):
                        for b7 in range(256):
                            current_key_bytes = bytes([b1, b2, b3, b4, b5, b6, b7])
                            
                            aes_key = hashlib.sha256(current_key_bytes).digest()
                            cipher = AES.new(aes_key, AES.MODE_ECB)
                            try:
                                decrypted_flag = cipher.decrypt(given_enc_bytes)
                                if decrypted_flag.startswith(b"ACE{"):
                                    found_key = current_key_bytes
                                    print("Found 7-byte key: %s (hex: %s)" % (found_key.hex(), found_key))
                                    print("Decrypted Flag: %s" % decrypted_flag.decode('utf-8', errors='ignore'))
                                    break
                            except ValueError:
                                # This can happen if the key is wrong and decryption fails
                                pass
                        if found_key: break
                    if found_key: break
                if found_key: break
            if found_key: break
        if found_key: break
    if found_key: break

if not found_key:
    print("7-byte key not found.")
    cipher = AES.new(aes_key, AES.MODE_ECB)
    decrypted_flag = cipher.decrypt(given_enc_bytes)
    print("Decrypted Flag: %s" % decrypted_flag)
else:
    print("7-byte key not found.")
