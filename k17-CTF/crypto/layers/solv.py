import sys
from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import unpad

# Mute pwntools logging
context.log_level = 'error'

def solve():
    """
    Solves the layered encryption challenge by exploiting a padding oracle vulnerability.
    """
    try:
        # Connect to the remote server
        conn = remote('challenge.secso.cc', 7004)
        print("🔗 Connected to the challenge server.")
    except Exception as e:
        print(f"❌ Failed to connect: {e}")
        return

    # --- Part 1: Preparation ---
    
    # The server first prints aes_c from the encrypt() method. Read and discard it.
    conn.recvline()

    # Now, read the public key parameters
    n_line = conn.recvline().decode().strip() # Receives "e.n = ..."
    n = int(n_line.split(' = ')[1])

    e_line = conn.recvline().decode().strip() # Receives "e.e = ..."
    e = int(e_line.split(' = ')[1])

    conn.recvline() # Welcome message
    challenge_line = conn.recvline().decode().strip()
    triplet_str = challenge_line.split(": ")[1]
    r, c, s = map(int, triplet_str.strip("()").split(", "))

    print("✅ Received public parameters and ciphertext.")
    
    # Calculate the original AES ciphertext (iv || ct) from the provided values
    m_prime = pow(s, e, n)
    aes_c_long = (m_prime * r) % n
    
    # Determine the correct length of the AES ciphertext (must be a multiple of 16)
    byte_len = (aes_c_long.bit_length() + 7) // 8
    total_len = ((byte_len + 15) // 16) * 16
    aes_c_bytes = aes_c_long.to_bytes(total_len, 'big')
    
    iv_orig = aes_c_bytes[:16]
    ct_orig = aes_c_bytes[16:]
    
    # Split the original ciphertext into blocks for the attack
    blocks = [iv_orig] + [ct_orig[i:i+16] for i in range(0, len(ct_orig), 16)]
    num_blocks = len(blocks) - 1
    
    print(f"🎯 Target ciphertext has {num_blocks} blocks. Starting oracle attack...")

    # --- Part 2: Padding Oracle Attack ---
    
    # --- THIS IS THE CORRECTED PART ---
    decrypted_plaintext = b""
    # --- END OF CORRECTION ---

    # Iterate over each block of the ciphertext, from last to first
    for block_idx in range(num_blocks, 0, -1):
        C_i = blocks[block_idx]       # Current block to decrypt
        C_prev = blocks[block_idx - 1] # Previous block (or IV) used for XOR
        
        decrypted_block = bytearray(16)
        intermediate_block = bytearray(16)
        
        print(f"\n⏳ Decrypting block {block_idx}/{num_blocks}...")

        # Iterate over each byte of the block, from last to first
        for byte_idx in range(15, -1, -1):
            padding_val = 16 - byte_idx
            crafted_block = bytearray(b'\x00' * 16)

            # Prepare the suffix of the crafted block to create the correct padding
            for i in range(byte_idx + 1, 16):
                crafted_block[i] = intermediate_block[i] ^ padding_val

            # Brute-force the current byte
            found_byte = False
            for g in range(256):
                crafted_block[byte_idx] = g
                
                M_bytes = b'\x00' * 16 + crafted_block + C_i
                r_guess = bytes_to_long(M_bytes)
                
                payload = f"{r_guess},1,1".encode()
                conn.sendlineafter(b"Prithee, tell in a comma-separated triplet, what secret do i hold? ", payload)
                
                response = conn.recvline().strip()
                
                # A robust check: any response that is NOT the padding error is a success.
                if b"doing" not in response:
                    intermediate_byte = g ^ padding_val
                    plaintext_byte = intermediate_byte ^ C_prev[byte_idx]
                    
                    intermediate_block[byte_idx] = intermediate_byte
                    decrypted_block[byte_idx] = plaintext_byte
                    
                    sys.stdout.write(f"\r   -> Found byte {16-byte_idx}/16: '{chr(plaintext_byte)}' ({hex(plaintext_byte)})")
                    sys.stdout.flush()

                    found_byte = True
                    break
            
            if not found_byte:
                print(f"\n❌ Error: Could not find byte at index {byte_idx} for block {block_idx}. Aborting.")
                conn.close()
                return

        decrypted_plaintext = bytes(decrypted_block) + decrypted_plaintext

    # --- Part 3: Finalization ---
    print("\n\n✅ Attack complete. All blocks decrypted.")
    
    try:
        flag = unpad(decrypted_plaintext, 16)
        print(f"\n🎉 FLAG: {flag.decode()}")
    except ValueError as e:
        print(f"\n⚠️ Unpadding failed: {e}")
        print(f"   Raw decrypted data (hex): {decrypted_plaintext.hex()}")

    conn.close()

if __name__ == "__main__":
    solve()