def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

def xor_decrypt(encrypted_data, key):
    decrypted_bytes = bytearray()
    key_len = len(key)
    for i, byte in enumerate(encrypted_data):
        decrypted_bytes.append(byte ^ key[i % key_len])
    return decrypted_bytes

# Read the key from key.hex
with open('files/key.hex', 'r') as f:
    key_hex = f.read().strip()

# Read the encrypted message from encrypted_message.txt
# Using 'latin-1' encoding as it maps all 256 possible byte values to characters
with open('files/encrypted_message.txt', 'rb') as f:
    encrypted_message_bytes = f.read()

key_bytes = hex_to_bytes(key_hex)
decrypted_bytes = xor_decrypt(encrypted_message_bytes, key_bytes)

# Try to decode the decrypted bytes. 'latin-1' is a good starting point for byte-to-char mapping.
try:
    decrypted_text = decrypted_bytes.decode('latin-1')
    print(decrypted_text)
except UnicodeDecodeError:
    print("Could not decode with latin-1. Trying utf-8 with errors ignored.")
    decrypted_text = decrypted_bytes.decode('utf-8', errors='ignore')
    print(decrypted_text)
