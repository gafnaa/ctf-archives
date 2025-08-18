import os
from Crypto.Cipher import AES

def generate_aes_key(key_bytes):
    """
    Converts a 2-byte key into a 16-byte binary string representation for AES.
    This function mimics the key generation logic from the provided scripts.
    """
    if len(key_bytes) != 2:
        raise ValueError("Key must be 2 bytes long")
    # Convert each byte to its 8-bit binary representation and concatenate
    binary_key = bin(key_bytes[0])[2:].zfill(8) + bin(key_bytes[1])[2:].zfill(8)
    return binary_key.encode('utf-8')

def find_keys():
    """
    Performs a meet-in-the-middle attack to find the two 2-byte AES keys.
    This version targets the SECOND block of the known message.
    """
    # Known plaintext from johndoe.py (second 16 bytes)
    # The full message is b'scriptCTF{testtesttesttesttest!_'
    known_plaintext = b'esttesttesttest!'
    
    # The corresponding ciphertext from the pcap dump for the known plaintext
    # This is the second block of the result of cipher2.encrypt(cipher.encrypt(message))
    final_ciphertext = bytes.fromhex("019d85dd0b46e5c2190c31209fc57727")

    print("Starting meet-in-the-middle attack...")
    
    # Dictionary to store the results of encrypting the plaintext with every possible k1
    intermediate_ciphertexts = {}

    # 1. Forward Encryption Pass (Plaintext -> Intermediate)
    # Iterate through all 2^16 possible values for the first key (k1)
    print("Step 1: Building encryption table for all possible k1 keys...")
    for i in range(2**16):
        k1_bytes = i.to_bytes(2, 'big')
        try:
            aes_key1 = generate_aes_key(k1_bytes)
            cipher1 = AES.new(aes_key1, AES.MODE_ECB)
            # Encrypt the known plaintext with the current k1
            intermediate = cipher1.encrypt(known_plaintext)
            # Store the result: intermediate_ciphertext -> k1
            intermediate_ciphertexts[intermediate] = k1_bytes
        except ValueError:
            continue # Skip invalid key values if any
    
    print(f"Encryption table built with {len(intermediate_ciphertexts)} entries.")

    # 2. Backward Decryption Pass (Final Ciphertext -> Intermediate)
    # Iterate through all 2^16 possible values for the second key (k2)
    print("Step 2: Searching for a key match by decrypting...")
    for j in range(2**16):
        k2_bytes = j.to_bytes(2, 'big')
        try:
            aes_key2 = generate_aes_key(k2_bytes)
            cipher2 = AES.new(aes_key2, AES.MODE_ECB)
            # Decrypt the final ciphertext with the current k2
            decrypted_intermediate = cipher2.decrypt(final_ciphertext)
            
            # 3. Check for a match
            if decrypted_intermediate in intermediate_ciphertexts:
                # A match is found! We have found the keys.
                k1_found = intermediate_ciphertexts[decrypted_intermediate]
                k2_found = k2_bytes
                print("\nKeys found!")
                print(f"  k1 = {k1_found.hex()}")
                print(f"  k2 = {k2_found.hex()}")
                return k1_found, k2_found
        except ValueError:
            continue

    print("Keys not found. The attack was unsuccessful.")
    return None, None

def decrypt_secret(k1, k2):
    """
    Uses the found keys to decrypt the final secret from the server.
    """
    if not k1 or not k2:
        print("Cannot decrypt secret without valid keys.")
        return

    # These are the known keys from the server script
    k3 = b'BB'
    k4 = b'B}'
    
    # This is the initial secret sent to the server from the pcap
    # It is encrypted with k1 and k2
    enc_from_pcap = bytes.fromhex("19574ac010cc9866e733adc616065e6c019d85dd0b46e5c2190c31209fc57727")

    # This is the final encrypted secret from the server, encrypted with k3 and k4
    quad_encrypted_secret = bytes.fromhex("0239bcea627d0ff4285a9e114b660ec0e97f65042a8ad209c35a091319541837")
    
    # Generate the AES keys from the byte values
    aes_k1 = generate_aes_key(k1)
    aes_k2 = generate_aes_key(k2)
    aes_k3 = generate_aes_key(k3)
    aes_k4 = generate_aes_key(k4)

    # Create AES cipher objects
    cipher1 = AES.new(aes_k1, AES.MODE_ECB)
    cipher2 = AES.new(aes_k2, AES.MODE_ECB)
    cipher3 = AES.new(aes_k3, AES.MODE_ECB)
    cipher4 = AES.new(aes_k4, AES.MODE_ECB)

    # Decrypt the message step-by-step
    # The server does: cipher4.encrypt(cipher3.encrypt(enc_from_pcap))
    # So we decrypt in reverse order:
    decrypted_with_k4 = cipher4.decrypt(quad_encrypted_secret)
    decrypted_with_k3 = cipher3.decrypt(decrypted_with_k4)
    
    # Now we have the original 'enc' value, let's decrypt it further
    decrypted_with_k2 = cipher2.decrypt(decrypted_with_k3)
    original_secret = cipher1.decrypt(decrypted_with_k2)

    # The flag is the secret message + all four keys appended.
    # We decode with errors='ignore' in case the keys are not valid utf-8.
    flag = (original_secret.decode('utf-8', errors='ignore') + 
            k1.decode('utf-8', errors='ignore') + 
            k2.decode('utf-8', errors='ignore') + 
            k3.decode('utf-8', errors='ignore') + 
            k4.decode('utf-8', errors='ignore'))

    print("\n--- Decryption Complete ---")
    print(f"Final Flag: {flag}")


if __name__ == "__main__":
    found_k1, found_k2 = find_keys()
    decrypt_secret(found_k1, found_k2)
