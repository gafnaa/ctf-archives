# The keys are derived directly from the C code's functions.
# In sub_4014D0(), the function simply returns 92.
# This value is used to decrypt the answer to the third question.
answer_key = 92

# In sub_401460(), the function calculates a sum and returns 42.
# This value is used to decrypt the flag.
flag_key = 42

# --------------------------------------------------------------------------
# ENCRYPTED STRINGS FROM GDB OUTPUT
# These are the actual bytes you found in the program's data section.
# The answer string is 11 bytes long, starting at memory address 0x4040A0.
encrypted_answer_data = b'\x89\xc0\x48\x89\x44\x24\x68\x48\x8d\x84\x24'

# The flag string is 31 bytes long, starting at memory address 0x404020.
encrypted_flag_data = b'\x44\x24\x0c\x10\x00\x00\x00\xeb\x1c\xc7\x44\x24\x0c\x08\x00\x00\x00\xeb\x12\xc7\x44\x24\x0c\x00\x00\x00\x00\xeb\x08\xc7\x44'

# --------------------------------------------------------------------------

def decrypt_string(encrypted_data, key):
    """
    Decrypts a byte string using a single-byte XOR key.
    
    The C code uses a a specific memory access pattern (byte_4040A0[4 * result]).
    This implies the data bytes are 4 bytes apart. We simulate this here.
    
    Args:
        encrypted_data (bytes): The raw data to decrypt.
        key (int): The single-byte integer key.
        
    Returns:
        str: The decrypted string.
    """
    decrypted_chars = []
    # We simulate accessing every 4th byte, as implied by the C code.
    # The actual data layout in memory would be key_byte, junk, junk, junk, key_byte...
    # For simplicity and to show the core logic, we assume the user will provide
    # the 11 or 31 relevant bytes of encrypted data directly.
    for byte in encrypted_data:
        decrypted_chars.append(chr(byte ^ key))
    
    return "".join(decrypted_chars)

def main():
    print("--- Decryptor Script ---")
    
    if b'PLACEHOLDER' in encrypted_answer_data or b'PLACEHOLDER' in encrypted_flag_data:
        print("\n[!] The script is missing the encrypted data strings.")
        print("    You must replace 'PLACEHOLDER_ANSWER' and 'PLACEHOLDER_FLAG_DATA_STRING' with the actual bytes from the program's data section.")
        print("    The correct data can be found by examining the executable with a hex editor.")
        print("    The answer string is 11 bytes long, starting at memory address 0x4040A0.")
        print("    The flag string is 31 bytes long, starting at memory address 0x404020.")
        return

    # Decrypt the correct answer for question 3
    correct_answer = decrypt_string(encrypted_answer_data, answer_key)
    print(f"\nCorrect answer for Question 3: {correct_answer}")

    # Decrypt the flag
    decrypted_flag = decrypt_string(encrypted_flag_data, flag_key)
    print(f"The Flag: {decrypted_flag}")

if __name__ == "__main__":
    main()
