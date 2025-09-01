# The encrypted data array, copied from the decompiled C++ code.
encrypted_bytes = [
    121, 121, 100, 76, 64, 7, 64, 104, 6, 104, 91, 7, 65, 4,
    104, 69, 4, 65, 4, 69, 68, 6, 89, 80, 74
]

# The static XOR key used for encryption/decryption.
key = 0x37

# An empty list to store the decrypted characters.
decrypted_chars = []

# Loop through each byte in the encrypted data array.
for byte in encrypted_bytes:
    # Perform the XOR operation with the key.
    decrypted_byte = byte ^ key
    # Convert the resulting integer back to a character and add it to our list.
    decrypted_chars.append(chr(decrypted_byte))

# Join all the characters in the list to form the final flag string.
flag = "".join(decrypted_chars)

# Print the recovered flag.
print(f"[*] Decrypted Flag: {flag}")
