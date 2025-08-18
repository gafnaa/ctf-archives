# This script translates the C++ decryptor logic into Python.
# It decrypts a password that was encrypted using a simple single-byte XOR cipher.

def decrypt(data: bytearray, key: int) -> bytearray:
    """
    Performs a simple XOR operation on each byte of the input data with a given key.
    Since XOR is its own inverse, this function can be used for both encryption and decryption.

    Args:
        data: A bytearray containing the data to be decrypted.
        key: An integer representing the XOR key.

    Returns:
        A new bytearray containing the decrypted data.
    """
    decrypted_data = bytearray()
    for byte in data:
        decrypted_data.append(byte ^ key)
    return decrypted_data

def main():
    """
    Main function to execute the decryption process.
    """
    # --- Analysis of the is_admin function from the decompiled code ---
    # The key for the XOR operation is stored as a signed char with the value -86.
    # In two's complement, -86 is represented as 0xAA.
    key = 0xAA

    # The 21-byte encrypted password is reconstructed from the stack variables
    # s2 and v4, considering the little-endian architecture.
    encrypted_password = bytearray([
        # Bytes from s2 (little-endian)
        0xFA, 0xEA, 0xD9, 0xD9, 0xDD, 0x9A, 0xD8, 0xCE,
        # First 13 bytes from v4 after the overwrite (little-endian)
        0xF5, 0x92, 0xCF, 0x98, 0xC2, 0x9F, 0x92, 0xDB,
        0xDE, 0x93, 0xDE, 0xDB, 0x9F
    ])

    # Decrypt the password by applying the same XOR operation.
    decrypted_password_bytes = decrypt(encrypted_password, key)

    # Decode the resulting bytes into a UTF-8 string to display the password.
    try:
        decrypted_password_str = decrypted_password_bytes.decode('utf-8')
    except UnicodeDecodeError:
        decrypted_password_str = "Error: Could not decode the result to a string."


    # Print the decrypted password to the console.
    print("Decryption Analysis Complete.")
    print(f"XOR Key (char -86): 0x{key:02x}")
    print(f"Decrypted Password: {decrypted_password_str}")

if __name__ == "__main__":
    main()
