import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. Gather public information from the challenge
KEY_SIZE_BITS = 256
MAX_INT = 1 << KEY_SIZE_BITS
MOD = MAX_INT - 189
SEED = MAX_INT // 5

alicePublic = 81967497404473670873986762408662347640688858544889917659709378751872081150739
bobPublic = 25638634989672271296647305730621408042240305773269414164982933528002524403752
ct_hex = "e2f84b71e84c8d696923702ddb1e35993e9108289e2d14ae8f05441ad48d1a67ead74f5f230d39dbfaae5709448c2690237ac6ab88fc26c8f362284d1e8063491d63f7c15cc3b024c62b5069605b73dd2c54fdcb2823c0c235b20e52dc5630c5f3"

# 2. Calculate the shared secret using the vulnerability
# Calculate SEED's modular inverse: SEED^(MOD-2) % MOD
seed_inv = pow(SEED, MOD - 2, MOD)

# Isolate P(alicePrivate) = alicePublic * seed_inv % MOD
p_alice_private = (alicePublic * seed_inv) % MOD

# Compute the shared secret = bobPublic * P(alicePrivate) % MOD
shared_secret = (bobPublic * p_alice_private) % MOD

# 3. Derive the AES key
# Convert shared secret to a 32-byte big-endian buffer
shared_bytes = shared_secret.to_bytes(32, 'big')

# Hash the buffer with SHA-256
aes_key = hashlib.sha256(shared_bytes).digest()

# 4. Decrypt the flag
# Parse the hex string into iv, ciphertext, and tag
ct_bytes = bytes.fromhex(ct_hex)
iv = ct_bytes[:12]
ciphertext_and_tag = ct_bytes[12:] # The library expects ciphertext and tag concatenated

# Perform AES-256-GCM decryption
aesgcm = AESGCM(aes_key)
try:
    plaintext_bytes = aesgcm.decrypt(iv, ciphertext_and_tag, None)
    flag = plaintext_bytes.decode('utf-8')
    print(f"✅ Decryption Successful!\n")
    print(f"🚩 Flag: {flag}")
except Exception as e:
    print(f"❌ Decryption Failed: {e}")