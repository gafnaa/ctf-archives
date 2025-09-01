def decrypt_password():
    """
    This function decrypts a hardcoded password string using a simple XOR cipher.
    """
    # The encrypted string from the original C code's global variable g1.
    encrypted_password = "Vio+C(rC/(ffeCl/(ffeCp/q,rrComi-ffe=="
    
    # The XOR key used in the encryption loop.
    key = 28
    
    # A list to hold the decrypted characters.
    decrypted_chars = []
    
    print("Decrypting the password...")
    
    # Loop through each character of the encrypted password.
    # ord() gets the integer value of the character.
    # The integer value is XORed with the key.
    # chr() converts the new integer value back to a character.
    for char in encrypted_password:
        decrypted_char = chr(ord(char) ^ key)
        decrypted_chars.append(decrypted_char)
        
    # Join the list of characters into a single string.
    decrypted_password = "".join(decrypted_chars)
    
    # Print the final decrypted password.
    print(f"Decrypted Password: {decrypted_password}")

if __name__ == "__main__":
    decrypt_password()
