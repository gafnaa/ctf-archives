import struct

# Helper functions to convert between bytes and 64-bit integers
p64 = lambda x: struct.pack('<Q', x)
u64 = lambda x: struct.unpack('<Q', x)[0]

def decrypt(ciphertext, key):
    """The decryption function from the challenge script."""
    iv, ciphertext = ciphertext[:8], ciphertext[8:]
    plaintext = b''
    for i in range(0, len(ciphertext), 8):
        c_block = ciphertext[i:i+8]
        p_block = p64(u64(iv) ^ u64(c_block) ^ u64(key))
        plaintext += p_block
        iv = c_block
    return plaintext

def unpad(padded_plaintext):
    """Correctly removes PKCS#7 style padding."""
    pad_len = padded_plaintext[-1]
    return padded_plaintext[:-pad_len]

# The ciphertext from the challenge
enc_hex = "a6d869161e868078527902778bb36050aca976082df6ba6b550a126ba3ec244fac93043e2dffb968551d1169a3e7244880cd593433d2cb5a676c3e55a3e7244880cd593433d2cb5a676c3e55a3e7244880cd593433d2cb5a676c3e55a3e7244880cd593433d2cb5a2e25771ceaae6d01"
enc_bytes = bytes.fromhex(enc_hex)

# Split the ciphertext into 8-byte blocks
blocks = [enc_bytes[i:i+8] for i in range(0, len(enc_bytes), 8)]

# C0 is the IV, C1 is the first block, etc.
c7_int = u64(blocks[7])
c8_int = u64(blocks[8])

# We know P8 is a block of 'A's
p8_int = u64(b'AAAAAAAA')

# Recover the key using the formula K = C7 ^ C8 ^ P8
key_int = c7_int ^ c8_int ^ p8_int
key_bytes = p64(key_int)

print(f"🔑 Recovered Key: {key_bytes.hex()}")

# Decrypt the full ciphertext with the recovered key
padded_flag = decrypt(enc_bytes, key_bytes)

# The original flag was padded with 'A's, then with PKCS#7 padding.
# First, remove the PKCS#7 padding.
flag_with_A_padding = unpad(padded_flag)

# Then, strip the trailing 'A's.
flag = flag_with_A_padding.rstrip(b'A')

print(f"🚩 Decrypted Flag: {flag.decode()}")