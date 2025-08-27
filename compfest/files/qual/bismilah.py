# This script must be run in a SageMath environment (e.g., `sage -python decryptor.sage`)
# Make sure you have pycryptodome installed in your Sage environment:
# sage -pip install pycryptodome

import hashlib
import ast
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sage.all import *

def parse_encrypted_file(filename):
    """Parses the encrypted.txt file to extract crypto parameters."""
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    ciphertext = bytes.fromhex(lines[0].strip().split(': ')[1])
    mod = int(lines[1].strip().split(': ')[1])
    a = ast.literal_eval(lines[2].strip().split('Given1: ')[1])
    b = ast.literal_eval(lines[3].strip().split('Given2: ')[1])
    
    return ciphertext, mod, a, b

def solve_and_decrypt_svp(a, b, mod, k, n, ciphertext):
    """
    Solves the Hidden Number Problem as a Shortest Vector Problem (SVP).
    The vector (s_0, ..., s_{n-1}, g_0, ..., g_{k-1}) is a short vector
    in the lattice described by the basis matrix B.
    """
    print("[+] Using SVP approach for Hidden Number Problem.")

    # 1. Construct the matrix C where C_ij = (b_i * a_ij) % mod
    print("[+] Constructing problem matrix C...")
    C = Matrix(ZZ, k, n)
    for i in range(k):
        for j in range(n):
            C[i, j] = (b[i] * a[i][j]) % mod

    # 2. Construct the lattice basis matrix B
    # B = [ I_n | C^T     ]
    #     [ 0   | mod*I_k ]
    dim = n + k
    B = Matrix(ZZ, dim, dim)
    
    # Place I_n in the top-left
    B.set_block(0, 0, Matrix.identity(n))
    
    # Place C^T in the top-right
    B.set_block(0, n, C.transpose())
    
    # Place mod*I_k in the bottom-right
    B.set_block(n, n, Matrix.identity(k) * mod)

    # 3. Run LLL to find the shortest vectors in the lattice
    print(f"[+] Constructed SVP lattice of dimension {dim}x{dim}. Running LLL...")
    B_lll = B.LLL()
    
    print("[+] LLL complete. Searching for a valid key in the reduced basis...")

    # 4. The shortest vectors should be of the form (s | g) or -(s | g).
    # We check the first few vectors in the reduced basis.
    for i, v in enumerate(B_lll[:20]): # Check the first 20 short vectors
        
        # The first n elements are the potential key
        potential_key = list(v)[:n]
        
        private_key = None
        # Check if the key is in binary form [0, 1] or its negative [0, -1]
        if all(bit in [0, 1] for bit in potential_key):
            private_key = potential_key
        elif all(bit in [0, -1] for bit in potential_key):
            print(f"[i] Found key in negative form in vector {i}. Flipping signs.")
            private_key = [-x for x in potential_key]

        if private_key:
            print(f"[+] Found potential binary key in vector {i}. Attempting decryption...")
            decrypted_flag = decrypt_flag(ciphertext, private_key)
            if decrypted_flag:
                # Success! Padding was correct.
                return decrypted_flag, private_key

    print("[-] Exhausted candidate vectors. Could not find the correct key.")
    return None, None


def decrypt_flag(ciphertext, private_key):
    """
    Decrypts the AES-ECB ciphertext. Returns decrypted data on success, None on failure.
    """
    try:
        key_bytes = bytes(private_key)
        aes_key = hashlib.sha256(key_bytes).digest()
        cipher = AES.new(aes_key, AES.MODE_ECB)
        decrypted_padded = cipher.decrypt(ciphertext)
        return unpad(decrypted_padded, AES.block_size)
    except ValueError:
        print("[-] Decryption failed with this key (incorrect padding).")
        return None
    except Exception as e:
        print(f"[-] An unexpected error occurred during decryption: {e}")
        return None

if __name__ == "__main__":
    K, N = 64, 128
    FILENAME = 'encrypted.txt'
    
    print(f"[+] Reading data from {FILENAME}...")
    ct, p, A, B = parse_encrypted_file(FILENAME)
    
    flag, key = solve_and_decrypt_svp(A, B, p, K, N, ct)
    
    if flag:
        print(f"\n[+] Successfully recovered private key of length {len(key)}.")
        print("\n" + "="*40)
        print(f"[*] SUCCESS! Flag: {flag.decode()}")
        print("="*40)
    else:
        print("\n" + "="*40)
        print("[!] Failed to recover the key and decrypt the flag.")
        print("="*40)
