import os
from Crypto.Cipher import AES
import itertools

def generate_final_key(key):
    """Converts a 2-byte key into the 16-byte binary string format used by the scripts."""
    if len(key) != 2:
        raise ValueError("Key must be 2 bytes long")
    return (bin(key[0])[2:].zfill(8) + bin(key[1])[2:].zfill(8)).encode()

def main():
    """
    This script decrypts a message that has been encrypted multiple times with AES in ECB mode.
    It works by brute-forcing the first two keys (k1, k2), which are known to be 2 bytes each.
    """
    # Known plaintext and ciphertexts from the problem description and pcap file
    known_plaintext = b'scriptCTF{testtesttesttesttest!_'
    # This is the hex string of the message encrypted with k1 and k2
    ciphertext_from_johndoe = bytes.fromhex("19574ac010cc9866e733adc616065e6c019d85dd0b46e5c2190c31209fc57727")
    # This is the final ciphertext, encrypted with k1, k2, k3, and k4
    quadruple_encrypted = bytes.fromhex("0239bcea627d0ff4285a9e114b660ec0e97f65042a8ad209c35a091319541837")

    # Keys k3 and k4 are known from the server script
    k3 = b'BB'
    k4 = b'B}'
    final_k3 = generate_final_key(k3)
    final_k4 = generate_final_key(k4)

    found_k1 = None
    found_k2 = None

    print("Starting brute-force attack to find k1 and k2...")

    # Generate all possible 2-byte keys
    possible_bytes = [i.to_bytes(1, 'big') for i in range(256)]
    possible_keys = [b''.join(p) for p in itertools.product(possible_bytes, repeat=2)]

    for k1_candidate in possible_keys:
        for k2_candidate in possible_keys:
            try:
                final_k1 = generate_final_key(k1_candidate)
                final_k2 = generate_final_key(k2_candidate)

                cipher1 = AES.new(final_k1, mode=AES.MODE_ECB)
                cipher2 = AES.new(final_k2, mode=AES.MODE_ECB)

                # Encrypt the known plaintext with the candidate keys
                encrypted_once = cipher1.encrypt(known_plaintext)
                encrypted_twice = cipher2.encrypt(encrypted_once)
                
                # Check if the output matches the first 16 bytes of the captured ciphertext
                if encrypted_twice[:16] == ciphertext_from_johndoe[:16]:
                    found_k1 = k1_candidate
                    found_k2 = k2_candidate
                    print(f"\n[+] Found Keys!")
                    print(f"    k1: {found_k1.hex()} ({found_k1})")
                    print(f"    k2: {found_k2.hex()} ({found_k2})")
                    break
            except Exception as e:
                # This can happen with invalid key data, but we can ignore it.
                pass
        if found_k1:
            break
            
    if not found_k1 or not found_k2:
        print("\n[-] Failed to find the keys. The ciphertext or logic might be different than expected.")
        return

    # Now that we have all the keys, we can decrypt the final message.
    print("\nDecrypting the final message with all four keys...")

    # The server encrypts the user's input with k3 and k4.
    # The user's input was already encrypted with k1 and k2.
    # So, the quadruple_encrypted value is E_k4(E_k3(E_k2(E_k1(original_message))))
    # To decrypt, we reverse the process: D_k1(D_k2(D_k3(D_k4(quad_encrypted))))
    
    final_k1 = generate_final_key(found_k1)
    final_k2 = generate_final_key(found_k2)

    cipher1 = AES.new(final_k1, mode=AES.MODE_ECB)
    cipher2 = AES.new(final_k2, mode=AES.MODE_ECB)
    cipher3 = AES.new(final_k3, mode=AES.MODE_ECB)
    cipher4 = AES.new(final_k4, mode=AES.MODE_ECB)

    decrypted_by_k4 = cipher4.decrypt(quadruple_encrypted)
    decrypted_by_k3 = cipher3.decrypt(decrypted_by_k4)
    decrypted_by_k2 = cipher2.decrypt(decrypted_by_k3)
    decrypted_by_k1 = cipher1.decrypt(decrypted_by_k2)
    
    # The flag is the decrypted message plus the keys
    flag = decrypted_by_k1 + found_k1 + found_k2 + k3 + k4
    
    print("\n[+] Decryption successful!")
    try:
        print(f"    Flag: {flag.decode()}")
    except UnicodeDecodeError:
        print(f"    Flag (raw): {flag}")
        print(f"    Flag (hex): {flag.hex()}")


if __name__ == "__main__":
    main()
