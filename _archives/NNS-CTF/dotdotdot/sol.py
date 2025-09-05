from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# The base key is the bundle GUID found at the end of the executable file.
base_key_hex = 'd38cc827e34f44539df41e796e9f1d07'
base_key_bytes = bytes.fromhex(base_key_hex)

# The correct ciphertext is the 32-byte string found at the end of the .exe file.
ct_hex = '8B0110B96A611038727B931010D7A03210F5B9E6EFAE3310EE3B2DCE24B36AAE'
ciphertext = bytes.fromhex(ct_hex)

# --- Key Transformation ---
# The key is transformed in two steps: a Caesar shift followed by a repeating-key XOR.
caesar_offset = 5
xor_key = b"tore"

# 1. First, apply the Caesar shift. The direction is addition, not subtraction.
caesared_key = bytearray()
for b in base_key_bytes:
    caesared_key.append((b + caesar_offset) & 0xFF)

# 2. Second, apply the repeating-key XOR to the result of the Caesar operation.
final_key = bytearray()
for i in range(len(caesared_key)):
    final_key.append(caesared_key[i] ^ xor_key[i % len(xor_key)])

# Create a new AES cipher object with the now-correct key.
cipher = AES.new(final_key, AES.MODE_ECB)

# Decrypt the ciphertext.
try:
    decrypted_padded = cipher.decrypt(ciphertext)

    # Unpad the decrypted bytes using PKCS7 padding.
    decrypted = unpad(decrypted_padded, AES.block_size)

    # Decode from bytes to a string and print the flag.
    flag = decrypted.decode('utf-8')
    print(f"[+] Decryption Successful!")
    print(f"[*] Final Key (Hex): {final_key.hex()}")
    print(f"[+] Flag: {flag}")

except (ValueError, KeyError) as e:
    print(f"[-] Decryption failed.")
    print(f"[*] Final Key (Hex): {final_key.hex()}")
    print(f"    Error: {e}")
    print(f"    This might still be due to an incorrect key or ciphertext.")

