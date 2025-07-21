

import hashlib
import sys
from Crypto.Cipher import AES

def find_key():
    """
    Recovers the 7-byte key by reversing Python 2.7's hash function
    using a meet-in-the-middle attack.
    """
    # --- Constants for the hash algorithm ---
    TARGET_HASH = 0x3d9977528e9d2ce5
    P = 1000003  # The multiplier from Python's hash algorithm
    MASK = (1 << 64) - 1 # 64-bit mask

    # Pre-calculated modular multiplicative inverse of P mod 2^64
    # P_inv = pow(P, -1, 2**64)
    P_INV = 0x30310853a463b2ad

    # --- Part 1: Forward Calculation (Build Lookup Table) ---
    # We split the key into 3 bytes (forward) and 4 bytes (backward).
    # The table will store the hash state after the first 3 bytes.
    
    print("[*] Building lookup table for the first 3 key bytes...")
    lookup_table = {}
    
    # Iterate through all 256^3 possibilities for k0, k1, k2
    for k0 in range(256):
        # Calculate initial hash state based on the first byte (k0)
        h_neg_1 = k0 << 7
        h0 = (((P * h_neg_1) & MASK) ^ k0) & MASK
        
        for k1 in range(256):
            h1 = (((P * h0) & MASK) ^ k1) & MASK
            
            for k2 in range(256):
                h2 = (((P * h1) & MASK) ^ k2) & MASK
                # Store the result with the bytes that produced it
                # Using bytes as key for direct reconstruction later
                lookup_table[h2] = chr(k0) + chr(k1) + chr(k2)

    print("[+] Lookup table built with %d entries." % len(lookup_table))
    print("[*] Searching for the remaining 4 key bytes...")

    # --- Part 2: Backward Calculation (Search for a Match) ---
    # We start from the final hash and work backwards to find a hash state
    # that matches one of the entries in our lookup_table.

    # The final hash is XORed with the length of the key (7)
    h6 = TARGET_HASH ^ 7
    
    # Iterate through all 256^4 possibilities for k6, k5, k4, k3
    for k6 in range(256):
        # Print progress update
        if k6 % 16 == 0:
            sys.stdout.write("    -> Progress: k6 = %d/255\r" % k6)
            sys.stdout.flush()

        # Reverse the last step to get h5
        h5 = (((h6 ^ k6) * P_INV) & MASK)
        
        for k5 in range(256):
            # Reverse to get h4
            h4 = (((h5 ^ k5) * P_INV) & MASK)
            
            for k4 in range(256):
                # Reverse to get h3
                h3 = (((h4 ^ k4) * P_INV) & MASK)

                for k3 in range(256):
                    # Reverse to get our candidate for h2
                    h2_candidate = (((h3 ^ k3) * P_INV) & MASK)
                    
                    # Check if this state is in our lookup table
                    if h2_candidate in lookup_table:
                        # --- COLLISION FOUND ---
                        key_part1 = lookup_table[h2_candidate]
                        key_part2 = chr(k3) + chr(k4) + chr(k5) + chr(k6)
                        found_key = key_part1 + key_part2
                        
                        print("\n[+] Key Found!")
                        return found_key

    print("\n[-] Key not found. Ensure you are running 64-bit Python 2.7.")
    return None

if __name__ == '__main__':
    # --- Step 1: Recover the 7-byte key ---
    key = find_key()

    if key:
        print("    - Recovered 7-byte key: %r" % key)
        print("    - Hash of recovered key: %s" % hex(hash(key))[2:])

        # --- Step 2: Use the key to decrypt the ciphertext ---
        print("\n[*] Decrypting the message...")
        
        # The provided ciphertext from the challenge
        enc_hex = "7d9606e6dcf2f6d441e5e1efd9eb91afc32db2dc233cc1978eb090173eec1de81a5c7bd7a7f3358d35c781dd5cb64d69"
        enc = enc_hex.decode('hex')
        
        # Derive the AES key using SHA-256, as in the original script
        aes_key = hashlib.sha256(key).digest()
        
        # Create the AES cipher in ECB mode
        cipher = AES.new(aes_key, AES.MODE_ECB)
        
        # Decrypt the ciphertext
        decrypted_plaintext = cipher.decrypt(enc)
        
        print("[+] Decryption complete.")
        print("--- FLAG ---")
        print(decrypted_plaintext)