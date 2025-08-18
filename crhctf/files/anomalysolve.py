# This script decrypts the password from the provided C pseudocode.
# The core logic is based on the sub_40124c function, which performs
# a simple XOR operation on a block of memory.

def decrypt_code():
    """
    Replicates the decryption logic from the sub_40124c function.
    """
    # These are the 33 encrypted bytes you extracted from the binary
    # at address (base_address + 0x12c7) using GDB.
    encrypted_code = [
        0x60, 0x71, 0x6b, 0x60, 0x58, 0x56, 0x7c, 0x42,
        0x51, 0x10, 0x7c, 0x64, 0x67, 0x61, 0x7c, 0x48,
        0x12, 0x4d, 0x44, 0x7c, 0x13, 0x51, 0x7c, 0x64,
        0x73, 0x77, 0x7c, 0x48, 0x4f, 0x4d, 0x44, 0x1c,
        0x1c
    ]

    # The key used in the XOR operation in the C code is the integer 35.
    xor_key = 35
    
    decrypted_chars = []
    
    # The loop in the C code runs 33 times.
    for byte in encrypted_code:
        # Perform the same XOR operation as the program.
        decrypted_byte = byte ^ xor_key
        decrypted_chars.append(chr(decrypted_byte))
        
    # Join the characters to form the final decrypted string.
    decrypted_password = "".join(decrypted_chars)
    
    print(f"Encrypted (Hex): {' '.join(f'0x{b:02x}' for b in encrypted_code)}")
    print("-" * 20)
    print(f"Decrypted Password: {decrypted_password}")

# Run the decryption function.
if __name__ == "__main__":
    decrypt_code()
