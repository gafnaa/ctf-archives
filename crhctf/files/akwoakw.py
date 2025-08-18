import binascii
import string

ciphertext_hex = "3b623a0a0f316f16791a0c6f1927440f6f0521340c6f113b0d080742161d0b6f4316174c5e2d791a14492d2a06016f462c4c4d020f"
ciphertext = bytes.fromhex(ciphertext_hex)

known_plaintext = b"CRHC{"

# Try several key lengths
for key_len in range(1, 13):
    # Derive key bytes for first known_plaintext_len bytes
    if key_len < len(known_plaintext):
        # We can only get key bytes for indices < key_len, others repeat
        key = bytearray(key_len)
        for i in range(len(known_plaintext)):
            key_byte = ciphertext[i] ^ known_plaintext[i]
            # key repeats every key_len, so key_byte should equal key[i % key_len]
            if i < key_len:
                key[i] = key_byte
            else:
                # Check consistency
                if key[i % key_len] != key_byte:
                    break
        else:
            # No breaks, key is consistent
            # try to decrypt whole ciphertext with this key
            plaintext = bytearray()
            for i, c in enumerate(ciphertext):
                plaintext.append(c ^ key[i % key_len])
            # Check if plaintext is printable ascii
            if all(chr(b) in string.printable for b in plaintext):
                print(f"Key length {key_len} found: key = {key}")
                print("Plaintext:", plaintext.decode())
                break
    else:
        # key_len >= known_plaintext length
        # Deduce key bytes from known plaintext bytes:
        key = bytearray(key_len)
        for i in range(len(known_plaintext)):
            key[i] = ciphertext[i] ^ known_plaintext[i]
        # For others in key, set to zero (we can't deduce)
        for i in range(len(known_plaintext), key_len):
            key[i] = 0
        # Decrypt full ciphertext with this key
        plaintext = bytearray()
        for i, c in enumerate(ciphertext):
            plaintext.append(c ^ key[i % key_len])
        if all(chr(b) in string.printable for b in plaintext):
            print(f"Key length {key_len} found (partial key): {key}")
            print("Plaintext:", plaintext.decode())
            break