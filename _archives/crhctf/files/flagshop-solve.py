# This program decrypts the flag from the provided C++ source code.
# The encryption logic is found in the `check_flag` function of the original file.
# Encryption: secret[i] = flag[i] ^ (23 * i + 3 + 7 * (i % 4))
# Decryption: flag[i] = secret[i] ^ (23 * i + 3 + 7 * (i % 4))

def decrypt_flag():
    """
    Decrypts the secret array to reveal the original flag.
    """
    # The secret array and its length, copied directly from the provided code.
    secret = [
        64, 115, 119, 30, 36, 8, 196, 222, 206, 234, 132, 294, 370, 337, 268,
        261, 324, 418, 496, 427, 510, 473, 620, 630, 579, 633, 528, 730, 739,
        660, 679, 702, 662, 862, 891, 781, 864, 876, 783, 934, 932, 902, 1000,
        970, 968, 1128
    ]
    length = 46

    # A list to hold the decrypted characters.
    decrypted_chars = []

    print("Starting decryption process...")

    # Loop through each element of the secret list.
    for i in range(length):
        # Calculate the key for the current position 'i'.
        # This is the exact same key generation logic from the check_flag function.
        key = (23 * i + 3 + 7 * (i % 4))

        # Decrypt the character by XORing the secret value with the key.
        original_char_code = secret[i] ^ key

        # Convert the character code to a character and add it to our list.
        decrypted_chars.append(chr(original_char_code))

    # Join the list of characters into a single string.
    decrypted_flag = "".join(decrypted_chars)

    # Print the final decrypted flag.
    print("Decryption complete!")
    print(f"The flag is: {decrypted_flag}")

# This ensures the script runs when executed directly.
if __name__ == "__main__":
    decrypt_flag()
