# simple-solve.py
#
# To run: sage -python simple-solve.py
# Make sure 'enc.txt' is in the same directory.

import ast
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import math

# --- FIX: Import necessary functions from the Sage library ---
from sage.all import Matrix, ZZ

def parse_file(filename):
    """Parses the encrypted.txt file to extract the crypto parameters."""
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    ciphertext_hex = lines[0].split(': ')[1].strip()
    ciphertext = bytes.fromhex(ciphertext_hex)
    
    mod = int(lines[1].split(': ')[1].strip())
    
    given1_str = lines[2].split('Given1: ')[1].strip()
    a = ast.literal_eval(given1_str)

    given2_str = lines[3].split('Given2: ')[1].strip()
    b = ast.literal_eval(given2_str)
    
    return ciphertext, mod, a, b

def solve_hnp_with_lll(mod, a, b):
    """
    Solves the Hidden Number Problem using LLL to find the private key.
    """
    k = len(a)    # Number of equations (64)
    n = len(a[0]) # Number of private key bits (128)
    
    print(f"[*] System parameters: n={n}, k={k}")
    
    # The upper bound for g_i, which is also a good scaling factor
    bound = int(math.sqrt(mod // 2))
    
    # A_ij = (b_i * a_ij) % mod
    A = [[(b[i] * a[i][j]) % mod for j in range(n)] for i in range(k)]
    
    # Construct the lattice basis matrix B
    dim = n + k
    B = Matrix(ZZ, dim, dim)
    
    W = bound # Use the bound as the scaling factor
    
    print("[*] Building the lattice basis matrix...")
    
    # Top-left block: W * I_n
    for j in range(n):
        B[j, j] = W
    
    # Top-right block: A^T (transpose of A)
    for i in range(k):
        for j in range(n):
            B[j, n + i] = A[i][j]
    
    # Bottom-right block: mod * I_k
    for i in range(k):
        B[n + i, n + i] = mod
    
    print("[*] Running the LLL algorithm... (this may take a few minutes)")
    # Apply LLL reduction to find a basis of short vectors
    B_lll = B.LLL()
    
    print("[*] LLL finished. Extracting the key from the shortest vector.")
    # The shortest vector is likely the first row of the LLL-reduced basis
    v_shortest = B_lll[0]
    
    # Extract the private key candidate by unscaling and rounding
    priv_key_candidate = []
    for j in range(n):
        # v_shortest[j] should be W * p_j, where p_j is 0 or 1.
        # So, we divide by W and round to the nearest integer.
        val = v_shortest[j] / W
        priv_key_candidate.append(int(round(val)))
        
    # Check if the recovered key is a valid binary vector
    is_valid = all(p in [0, 1] for p in priv_key_candidate)
    
    if is_valid:
        print("[+] Successfully recovered a valid binary private key!")
        return priv_key_candidate
    else:
        # It's possible the vector is -v_shortest
        priv_key_candidate_neg = [-x for x in priv_key_candidate]
        is_valid_neg = all(p in [0, 1] for p in priv_key_candidate_neg)
        if is_valid_neg:
            print("[+] Successfully recovered a valid binary private key (from negative vector)!")
            return priv_key_candidate_neg

    raise Exception("Could not recover a valid private key. LLL might have failed or the logic is flawed.")

def decrypt_flag(ciphertext, private_key):
    """Derives the AES key and decrypts the flag."""
    key_bytes = bytes(private_key)
    aes_key = hashlib.sha256(key_bytes).digest()
    cipher = AES.new(aes_key, AES.MODE_ECB)
    
    padded_flag = cipher.decrypt(ciphertext)
    
    try:
        flag = unpad(padded_flag, 16)
        return flag
    except ValueError as e:
        print(f"[-] Decryption failed: {e}")
        return None

def main():
    try:
        # 1. Parse the provided data file
        ciphertext, mod, a, b = parse_file('encrypted.txt')
        print("[+] File 'enc.txt' parsed successfully.")
        
        # 2. Solve for the private key using the lattice attack
        private_key = solve_hnp_with_lll(mod, a, b)
        
        # 3. Decrypt the flag with the recovered key
        flag = decrypt_flag(ciphertext, private_key)
        
        if flag:
            print("\n" + "="*40)
            print("🎉 Flag decrypted! 🎉")
            print(f"    {flag.decode()}")
            print("="*40)

    except FileNotFoundError:
        print("[-] Error: 'enc.txt' not found. Please ensure it's in the same directory.")
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()