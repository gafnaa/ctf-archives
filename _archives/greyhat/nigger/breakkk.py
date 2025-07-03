
from pwn import *

# Establish a connection to the remote server
p = remote('0.cloud.chals.io', 31561)
# The remote server is no longer active, so we use Pwntools' process module
# to simulate the interaction with the provided Python script locally.
# p = process(['python3', 'CrypTopiaSC.py'])


def solve():
    """
    Automates the exploitation of the keystream reuse vulnerability.
    """
    try:
        # --- Step 1: Receive the encrypted flag ---
        # Read the server's output until the "Oh, one last thing: " line
        p.recvuntil(b"Oh, one last thing: ")
        
        # Receive the next line, which contains the hex-encoded encrypted flag
        encrypted_flag_hex = p.recvline().strip().decode()
        log.info(f"Received Encrypted Flag (hex): {encrypted_flag_hex}")
        
        # Convert hex to bytes
        encrypted_flag_bytes = bytes.fromhex(encrypted_flag_hex)
        flag_len = len(encrypted_flag_bytes)
        log.info(f"Flag length is {flag_len} bytes.")

        # --- Step 2: Send known plaintext ---
        # Create a known plaintext of the same length as the flag
        known_plaintext = b"A" * flag_len
        
        # Find the input prompt and send our known plaintext
        p.recvuntil(b"Enter your message: ")
        p.sendline(known_plaintext)
        log.info(f"Sent known plaintext: {known_plaintext.decode()}")
        
        # --- Step 3: Receive the ciphertext of our known plaintext ---
        known_ciphertext_hex = p.recvline().strip().decode()
        log.info(f"Received Ciphertext of 'A's (hex): {known_ciphertext_hex}")
        known_ciphertext_bytes = bytes.fromhex(known_ciphertext_hex)
        
        # --- Step 4: Decrypt the flag ---
        # The core of the exploit: Flag = EncryptedFlag ⊕ CiphertextForA ⊕ PlaintextA
        # This works because: (Flag ⊕ Key) ⊕ (P_known ⊕ Key) ⊕ P_known = Flag
        
        # XOR the two ciphertexts together
        intermediate_xor = xor(encrypted_flag_bytes, known_ciphertext_bytes)
        
        # XOR the result with our known plaintext to get the flag
        flag = xor(intermediate_xor, known_plaintext)
        
        # --- Step 5: Print the result ---
        log.success(f"🚩 Recovered Flag: {flag.decode()}")

    except Exception as e:
        log.error(f"An error occurred: {e}")
    
    finally:
        # Close the connection
        p.close()

if __name__ == "__main__":
    solve()