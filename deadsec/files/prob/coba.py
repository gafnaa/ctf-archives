import struct

def decrypt_block(v, k):
    """
    Decrypts a 64-bit block using a 128-bit key for ONE full cycle.
    This function reverses the logic found in the `main_sub_1269` function,
    which performs a 24-round custom Feistel cipher.
    """
    # Unpack the 8-byte block into two 4-byte unsigned integers (little-endian)
    v0, v1 = struct.unpack('<II', v)
    # Unpack the 16-byte key into four 4-byte unsigned integers
    k0, k1, k2, k3 = struct.unpack('<IIII', k)
    
    # The delta is a constant used in each round.
    # 322410905 in decimal is 0x13371337 in hexadecimal.
    delta = 322410905
    
    # The encryption runs 24 rounds. The sum 's' accumulates the delta.
    # For decryption, we start with the sum from the end of the encryption.
    # The sum for the last round (round 23) is 23 * delta.
    s = (23 * delta) & 0xFFFFFFFF

    # The loop runs 24 times to reverse the 24 internal rounds of encryption.
    for _ in range(24):
        # The sum term used in the original encryption is (current_sum + delta)
        sum_term = (s + delta) & 0xFFFFFFFF
        
        # Reverse the update to the second part of the block (v1)
        # This reverses: v14 += (a12 + (v13 >> 6)) ^ (v16 + v13 + 322410905) ^ (a13 + 8 * v13);
        v1_update = ((k2 + (v0 >> 6)) ^ (sum_term + v0) ^ (k3 + (v0 * 8))) & 0xFFFFFFFF
        v1 = (v1 - v1_update) & 0xFFFFFFFF
        
        # Reverse the update to the first part of the block (v0)
        # This reverses: v13 += (a10 + (v14 >> 6)) ^ (v16 + v14 + 322410905) ^ (a11 + 8 * v14);
        v0_update = ((k0 + (v1 >> 6)) ^ (sum_term + v1) ^ (k1 + (v1 * 8))) & 0xFFFFFFFF
        v0 = (v0 - v0_update) & 0xFFFFFFFF
        
        # Decrement the sum for the next round of decryption
        s = (s - delta) & 0xFFFFFFFF
        
    # Pack the two decrypted integers back into an 8-byte block
    return struct.pack('<II', v0, v1)

def decrypt_full_block(block, key):
    """
    Performs the full decryption on a single block.
    The original program calls the main encryption function `main_sub_1269`
    a total of 24 times for each block (via the recursive `main_sub_1400`).
    Therefore, we must apply our `decrypt_block` function 24 times.
    """
    for _ in range(24):
        block = decrypt_block(block, key)
    return block

def main():
    """
    Main function to perform the decryption of the hardcoded ciphertext.
    The decrypted result is the required input for the original program.
    """
    # This is the encrypted data from `main_main` at `v30`. This is the target
    # value that the user's input, after encryption, must match.
    encrypted_data = [
        0x380E2A88B0F596D,
        0xD514FEC3D399E3AA,
        0xD831580A81972FD4,
        0xDD5B0F7162B1C82A,
        0x536AB62511E8D05E,
        0xFE7BEA51B181050F
    ]

    # The actual key is stored in `xmmword_55C250` in the executable.
    # We continue to use the guessed key based on the prominent delta constant.
    key_dword = 0x13371337
    key = struct.pack('<IIII', key_dword, key_dword, key_dword, key_dword)

    # Convert the list of 8-byte QWORDs to a single byte string
    encrypted_bytes = b''.join(struct.pack('<Q', q) for q in encrypted_data)
    
    decrypted_result = b''
    
    print("--- Decrypting Target Data to Find Required Input (Attempt 2) ---")
    print(f"Target Ciphertext (hex): {encrypted_bytes.hex()}")
    print(f"Guessed Key (hex):       {key.hex()}")
    print("-" * 65)

    # Decrypt the data one 8-byte block at a time using the full decryption function
    for i in range(0, len(encrypted_bytes), 8):
        block = encrypted_bytes[i:i+8]
        decrypted_block = decrypt_full_block(block, key)
        decrypted_result += decrypted_block
        print(f"Block {i//8}: Ciphertext: {block.hex()} -> Plaintext: {decrypted_block.hex()}")

    print("-" * 65)
    print(f"Final Decrypted Hex: {decrypted_result.hex()}")
    
    # Attempt to decode the final result as a string, stripping null padding
    try:
        final_string = decrypted_result.decode('ascii').strip('\x00')
        print(f"\nSUCCESS! Required Input String: '{final_string}'")
    except UnicodeDecodeError:
        print("\nCould not decode the result as a valid ASCII string.")
        print("The result might be binary data or the guessed key is still wrong.")

if __name__ == "__main__":
    main()
