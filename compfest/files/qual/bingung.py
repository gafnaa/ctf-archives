#!/usr/bin/env sage
# LWE Decryptor for COMPFEST17 Challenge (SageMath Version)
#
# This script solves a crypto challenge based on the Hidden Number Problem,
# a variant of the Learning with Errors (LWE) problem.
#
# This version is specifically adapted to run inside the SageMath environment,
# leveraging its powerful, built-in functions for matrix operations and
# lattice reduction (LLL). This is much more efficient and avoids the
# installation issues of external libraries.
#
# The core idea is that we have a set of equations of the form:
# (a_i . s) * b_i = g_i (mod mod)
# where 's' is the secret private_key and 'g_i' is a small number.
# This can be rewritten as:
# (b_i * a_i) . s = g_i (mod mod)
#
# This structure allows us to build a lattice where one of the shortest vectors
# contains the secret key 's'. We use Sage's built-in LLL algorithm to find
# this short vector and recover the key.

import hashlib
import ast
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sage.all import *

# NOTE: When running this script with the 'sage' command, Sage's mathematical
# functions like Matrix() and ZZ are automatically imported and available.

def parse_input(filename="encrypted.txt"):
    """
    Parses the challenge's output file to extract the ciphertext, modulus, and
    the given vectors 'a' and 'b'.
    """
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()

        ciphertext_hex = lines[0].strip().split(': ')[1]
        ciphertext = bytes.fromhex(ciphertext_hex)

        mod = int(lines[1].strip().split(': ')[1])

        # Use ast.literal_eval for safe parsing of the string-formatted lists
        a_str = lines[2].strip().split('Given1: ')[1]
        a = ast.literal_eval(a_str)

        b_str = lines[3].strip().split('Given2: ')[1]
        b = ast.literal_eval(b_str)

        return ciphertext, mod, a, b
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        print("Please ensure it is in the same directory as the script.")
        return None, None, None, None
    except (ValueError, IndexError) as e:
        print(f"Error: Could not parse '{filename}'. The file format may be incorrect.")
        print(f"Details: {e}")
        return None, None, None, None


def solve_hnp_and_decrypt():
    """
    Main function to construct the lattice, run LLL, recover the key,
    and decrypt the flag using SageMath's native functions.
    """
    # 1. Parse the input data from the file
    ciphertext, mod, a, b = parse_input()
    if ciphertext is None:
        return

    k = len(a)
    n = len(a[0])
    print(f"[*] Successfully parsed data from encrypted.txt (k={k}, n={n})")

    # 2. Construct the matrix M for our lattice
    # M[i][j] = (b[i] * a[i][j]) % mod
    M = [[(b[i] * a[i][j]) % mod for j in range(n)] for i in range(k)]
    print("[*] Constructed intermediate matrix M")

    # 3. Construct the lattice basis matrix B using Sage's Matrix object
    dim = n + k
    # The 'Matrix' and 'ZZ' objects are provided by the Sage environment
    B = Matrix(ZZ, dim, dim) # Create a matrix over the integers

    # Top-left block: n x n Identity matrix
    for i in range(n):
        B[i, i] = 1

    # Top-right block: n x k matrix M^T (transpose of M)
    for i in range(n):
        for j in range(k):
            B[i, n + j] = M[j][i]

    # Bottom-right block: k x k diagonal matrix with 'mod' on the diagonal
    for i in range(k):
        B[n + i, n + i] = mod

    print(f"[*] Constructed {dim}x{dim} lattice basis B using SageMath Matrix")

    # 4. Run Sage's LLL algorithm to find a reduced basis
    print("[*] Running Sage's LLL algorithm... (this is usually fast)")
    # The .LLL() method is highly optimized and returns a new reduced basis
    reduced_B = B.LLL()
    print("[+] LLL reduction complete.")

    # 5. Iterate through the vectors of the reduced basis to find the key
    print("[*] Searching for the key in the reduced basis vectors...")
    found_key = False
    for i, short_vector in enumerate(reduced_B):
        # Limit the search to a reasonable number of vectors
        if i > 20:
            break

        private_key_candidate = list(short_vector)[:n]

        # Check if this vector is a valid candidate (components are 0, 1, or -1)
        if all(x in [0, 1, -1] for x in private_key_candidate):
            print(f"[+] Found a potential key vector in row {i}.")
            private_key = [abs(int(x)) for x in private_key_candidate]

            # 6. Try to decrypt with this candidate key
            try:
                key_bytes = bytes(private_key)
                aes_key = hashlib.sha256(key_bytes).digest()
                
                cipher = AES.new(aes_key, AES.MODE_ECB)
                padded_flag = cipher.decrypt(ciphertext)
                
                flag = unpad(padded_flag, 16)

                # Check for printable ASCII characters to confirm the correct key
                if all(32 <= c < 128 for c in flag):
                    print("\n" + "="*40)
                    print("  [+] SUCCESS! Decryption successful.")
                    print(f"  FLAG: {flag.decode()}")
                    print("="*40)
                    found_key = True
                    break

            except ValueError as e:
                # Catches padding errors
                print(f"  [-] Decryption with key from row {i} failed: {e}")
            except Exception as e:
                print(f"  [-] An unexpected error occurred with key from row {i}: {e}")

    if not found_key:
        print("\n[-] Exhausted search of reduced basis vectors.")
        print("[-] Failed to find a valid key and decrypt the flag.")

if __name__ == "__main__":
    solve_hnp_and_decrypt()
