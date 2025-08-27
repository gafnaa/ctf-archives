# solve.py
# Usage: sage -python solve.py encrypted.txt
#
# Sage-based solver with auto-tuning scale S.

import sys
import ast
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from sage.all import matrix, ZZ

def parse_enc_file(path):
    with open(path, 'r') as f:
        data = f.read().strip().splitlines()
    ct_hex = None
    mod = None
    a_list = None
    b_list = None
    for line in data:
        if line.startswith("Ciphertext:"):
            ct_hex = line.split(":",1)[1].strip()
        elif line.startswith("Modulo:"):
            mod = int(line.split(":",1)[1].strip())
        elif line.startswith("Given1:"):
            txt = line.split(":",1)[1].strip()
            a_list = ast.literal_eval(txt)
        elif line.startswith("Given2:"):
            txt = line.split(":",1)[1].strip()
            b_list = ast.literal_eval(txt)
    return bytes.fromhex(ct_hex), mod, a_list, b_list

def try_decrypt_with_bits(bits, ciphertext):
    key = hashlib.sha256(bytes(bits)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    try:
        pt = unpad(cipher.decrypt(ciphertext), 16)
        if b"COMPFEST" in pt:
            return pt
    except Exception:
        return None
    return None

def build_lattice_and_reduce(a_mat, b_vec, mod, n, k, S):
    N = n + k + k
    B = matrix(ZZ, N, N)

    # diagonal for p_j
    for j in range(n):
        B[j, j] = S

    # equations
    for i in range(k):
        row_idx = n + i
        bi = b_vec[i]
        for j in range(n):
            coeff = (bi * a_mat[i][j]) % mod
            if coeff > mod // 2:
                coeff -= mod
            B[row_idx, j] = coeff
        B[row_idx, n + i] = -1
        B[row_idx, n + k + i] = mod

    # diagonals for g_i and t_i
    for i in range(k):
        B[n + i, n + i] = 1
        B[n + k + i, n + k + i] = max(1, mod // max(1, S))

    # bias
    B[N-1, N-1] = S * 2
    Mred = B.LLL()
    return Mred

def search_candidates(Mred, n, ciphertext):
    for r in range(min(30, Mred.nrows())):
        v = Mred.row(r)
        p_candidate = [int(v[i]) for i in range(n)]
        cand_sets = [
            [1 if x != 0 else 0 for x in p_candidate],
            [x % 2 for x in p_candidate]
        ]
        for bits in cand_sets:
            pt = try_decrypt_with_bits(bits, ciphertext)
            if pt is not None:
                return bits, pt
    return None, None

def main():
    if len(sys.argv) < 2:
        print("Usage: sage -python solve.py encrypted.txt")
        return
    ciphertext, mod, a_list, b_list = parse_enc_file(sys.argv[1])
    k = len(a_list)
    n = len(a_list[0])
    print(f"[*] Parsed k={k}, n={n}, modulus bits={mod.bit_length()}")

    # Try different scale factors
    scales = [2**e for e in range(8, 40, 4)]  # 2^8 .. 2^36
    for S in scales:
        print(f"[*] Trying scale S={S}")
        Mred = build_lattice_and_reduce(a_list, b_list, mod, n, k, S)
        bits, pt = search_candidates(Mred, n, ciphertext)
        if pt is not None:
            print("[+] Success with S =", S)
            print("[*] Key bits (first 64):", bits[:64], "...")
            print("[*] Plaintext:", pt.decode())
            return
    print("[-] No valid plaintext found after all scales. Try extending scale range.")

if __name__ == "__main__":
    main()
