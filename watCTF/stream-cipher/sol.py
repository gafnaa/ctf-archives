import numpy as np
from collections import Counter
import sys

# --- Configuration ---
CHUNK_SIZE = 256
ENCRYPTED_FILE = 'encrypted.bin'
PLAINTEXT_FILE = 'AIW.txt'
DECRYPTED_FILE = 'decrypted.txt'

# --- Helper Functions ---
def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XORs two byte strings."""
    return bytes([x ^ y for x, y in zip(a, b)])

def pad_chunk(data: bytes) -> bytes:
    """Pads a chunk to CHUNK_SIZE with null bytes."""
    return data + b'\0' * (CHUNK_SIZE - len(data))

# --- Main Decryption Logic ---

def find_plaintext_offset(ciphertext: bytes, full_plaintext: bytes) -> int:
    """
    Finds the starting offset of the plaintext by testing keystream candidates.
    This version correctly interprets the `str(counter) * 1337` logic.
    """
    print("[*] Searching for correct plaintext offset (0-1000)...")
    first_ct_block = ciphertext[:CHUNK_SIZE]
    
    # For counter=0, input is `b'0' * 1337`. This is 5 full blocks and a final partial block.
    # Since 5 is an odd number, the XOR sum of the permuted full blocks is just one
    # permuted block of `b'0'`. As a permutation of a uniform block is still that
    # uniform block, this simplifies to a block of `ord('0')`.
    # ks_0 = (block of ord('0')) ^ P(final_partial_block)
    # Therefore, ks_0 ^ (block of ord('0')) = P(final_partial_block)
    # The final partial block is `b'0'*57 + b'\0'*199`. The right side is a permutation
    # of this known chunk, so its byte counts are fixed.
    expected_counts = Counter({ord(b'0'): 57, 0: 199})
    constant_xor_block = bytes([ord(b'0')] * CHUNK_SIZE)

    for offset in range(1001):
        pt_candidate_block = full_plaintext[offset : offset + CHUNK_SIZE]
        if len(pt_candidate_block) < CHUNK_SIZE:
            continue

        # Recover the potential first keystream block
        keystream_candidate = xor_bytes(first_ct_block, pt_candidate_block)
        
        # Reverse the XOR from the full blocks to get the permuted chunk candidate
        permuted_chunk_candidate = xor_bytes(keystream_candidate, constant_xor_block)
        
        # Check if its byte counts match our expectation
        if Counter(permuted_chunk_candidate) == expected_counts:
            print(f"[+] Found correct offset: {offset}")
            return offset
            
    print("[-] Failed to find plaintext offset.", file=sys.stderr)
    sys.exit(1)

def recover_shared_key(ciphertext: bytes, plaintext: bytes) -> np.ndarray:
    """
    Recovers the secret permutation key using the known plaintext.
    This version uses counters 10-99 where the keystream is a direct permutation.
    """
    print("[*] Recovering the secret permutation key...")
    
    possibilities = [set(range(CHUNK_SIZE)) for _ in range(CHUNK_SIZE)]
    
    # For counters 10-99, len(str(i)) is 2. The input data length is 2*1337=2674.
    # The number of full chunks is 2674 // 256 = 10. Since 10 is even, the XOR sum
    # of the permuted full chunks is zero. This leaves ks_i = P(last_chunk),
    # giving us a direct relationship to solve for the key.
    num_blocks_to_solve = 20 
    print(f"[*] Using counters 10-{10 + num_blocks_to_solve -1} to solve...")

    for i in range(10, 10 + num_blocks_to_solve):
        # Determine the known input chunk for the permutation
        input_data = (str(i) * 1337).encode()
        last_chunk_len = len(input_data) % CHUNK_SIZE
        input_chunk = pad_chunk(input_data[-last_chunk_len:])
        
        # Recover the corresponding keystream block
        ct_block = ciphertext[i*CHUNK_SIZE : (i+1)*CHUNK_SIZE]
        pt_block = plaintext[i*CHUNK_SIZE : (i+1)*CHUNK_SIZE]
        keystream_block = xor_bytes(ct_block, pt_block) # This IS the permuted chunk
        
        # Narrow down possibilities based on this input/output pair
        for out_idx in range(CHUNK_SIZE):
            if len(possibilities[out_idx]) == 1:
                continue

            output_byte = keystream_block[out_idx]
            
            possible_input_indices = {
                in_idx for in_idx, in_byte in enumerate(input_chunk) 
                if in_byte == output_byte
            }
            
            possibilities[out_idx].intersection_update(possible_input_indices)

    print("[*] Performing elimination to solve remaining ambiguities...")
    solved_key = np.full(CHUNK_SIZE, -1, dtype=int)
    
    while -1 in solved_key:
        made_progress = False
        for i in range(CHUNK_SIZE):
            if solved_key[i] == -1 and len(possibilities[i]) == 1:
                value = possibilities[i].pop()
                solved_key[i] = value
                made_progress = True
                
                for j in range(CHUNK_SIZE):
                    if i != j and value in possibilities[j]:
                        possibilities[j].remove(value)
        
        if not made_progress:
            unsolved_count = sum(1 for s in possibilities if len(s) > 1)
            if unsolved_count > 0:
                 print(f"[-] Could not fully solve the key. {unsolved_count} ambiguous positions remain.", file=sys.stderr)
                 sys.exit(1)

    print("[+] Successfully recovered the shared_key!")
    return solved_key


def decrypt_file(shared_key: np.ndarray):
    """
    Decrypts the file using the recovered key.
    """
    print(f"[*] Decrypting {ENCRYPTED_FILE}...")
    
    # Re-implement the original script's functions with our recovered key
    def apply_perm(chunk):
        return np.array(list(chunk), dtype=np.uint8)[shared_key]

    def chf(data):
        state = np.zeros(CHUNK_SIZE, dtype=np.uint8)
        for i in range(0, len(data), CHUNK_SIZE):
            chunk = data[i:i+CHUNK_SIZE]
            chunk = pad_chunk(chunk)
            state ^= apply_perm(chunk)
        return bytes(state.tolist())

    def csprng():
        counter = 0
        while True:
            # Generate input using the correct string repetition logic
            input_data = (str(counter) * 1337).encode()
            yield chf(input_data)
            counter += 1

    with open(ENCRYPTED_FILE, 'rb') as f_in, open(DECRYPTED_FILE, 'wb') as f_out:
        keystream_gen = csprng()
        while True:
            cipher_block = f_in.read(CHUNK_SIZE)
            if not cipher_block:
                break
            
            keystream_block = next(keystream_gen)
            plain_block = xor_bytes(cipher_block, keystream_block)
            f_out.write(plain_block)

    print(f"[+] Decryption complete! Output saved to {DECRYPTED_FILE}")


if __name__ == "__main__":
    try:
        with open(ENCRYPTED_FILE, 'rb') as f:
            ciphertext = f.read()
        with open(PLAINTEXT_FILE, 'rb') as f:
            full_plaintext = f.read()
    except FileNotFoundError as e:
        print(f"[-] Error: {e}. Make sure '{ENCRYPTED_FILE}' and '{PLAINTEXT_FILE}' are in the same directory.", file=sys.stderr)
        sys.exit(1)

    offset = find_plaintext_offset(ciphertext, full_plaintext)
    
    plaintext = full_plaintext[offset:]
    
    key = recover_shared_key(ciphertext, plaintext)
    
    decrypt_file(key)

