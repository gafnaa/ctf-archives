# solve_final_crt.py
# Run with: sage -python solve_final_crt.py

import ast
import random
from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long

# SageMath imports
from sage.all import GF, PolynomialRing, inverse_mod, Matrix, vector, crt

# --- Correct MT19937 Solver ---
class MT19937Solver:
    def __init__(self):
        self.N = 624
        
    def solve(self, lsbs):
        F = GF(2)
        N = self.N
        
        log.info("Building the 19968x19968 transition matrix in-place...")
        temp_rng = random.Random()
        
        A = Matrix(F, N * 32, N * 32)

        for i in range(N * 32):
            state_list = [0] * N
            word_idx = i // 32
            bit_idx = i % 32
            state_list[word_idx] = 1 << bit_idx
            initial_state_tuple = (3, tuple(state_list + [N]), None)
            temp_rng.setstate(initial_state_tuple)
            col = [temp_rng.getrandbits(32) % 2 for _ in range(N * 32)]
            A[:, i] = vector(F, col)
            
            if (i + 1) % 1000 == 0:
                log.info(f"Generated {i+1}/{N*32} columns for the matrix...")

        b = vector(F, lsbs)
        log.info("Solving the 19968x19968 system... (this is computationally intensive)")
        state_bits = A.solve_right(b)
        log.success("System solved. Initial state bits recovered.")

        state_tuple_list = []
        for i in range(N):
            word = 0
            for j in range(32):
                if state_bits[i * 32 + j] == 1:
                    word |= (1 << j)
            state_tuple_list.append(word)
        
        return (3, tuple(state_tuple_list + [N]), None)

def solve():
    HOST, PORT = "ctf.compfest.id", 7101
    conn = remote(HOST, PORT)

    log.info("Collecting 19968 LSBs from the server...")
    lsbs = [0 if conn.recvline().strip() == b"even" else 1 for _ in range(19968)]
    log.success("All LSBs collected.")

    cracker = MT19937Solver()
    initial_state = cracker.solve(lsbs)

    cloned_rng = random.Random()
    cloned_rng.setstate(initial_state)
    
    log.info("Fast-forwarding cloned RNG to synchronize with server state...")
    for _ in range(19968):
        cloned_rng.getrandbits(32)
    log.success("RNG state synchronized.")
    
    log.info("Predicting the four 1024-bit noise values...")
    r1, r2, r3, r4 = [cloned_rng.getrandbits(1024) for _ in range(4)]
    log.success("Noise values predicted.")

    log.info("Receiving crypto parameters...")
    p = int(conn.recvline().strip().split(b" = ")[1])
    e = int(conn.recvline().strip().split(b" = ")[1])
    n = int(conn.recvline().strip().split(b" = ")[1])
    coeffs = ast.literal_eval(conn.recvline().strip().split(b" = ")[1].decode())
    c1_test_noisy = int(conn.recvline().strip().split(b" = ")[1])
    c2_test_noisy = int(conn.recvline().strip().split(b" = ")[1])
    c1_secret_noisy = int(conn.recvline().strip().split(b" = ")[1])
    c2_secret_noisy = int(conn.recvline().strip().split(b" = ")[1])
    conn.close()

    log.info("Recovering clean ciphertexts...")
    c1_test_clean = c1_test_noisy - r1
    c1_secret_clean = c1_secret_noisy - r3
    assert c1_test_clean == c1_secret_clean
    c2_test_clean = c2_test_noisy - r2
    c2_secret_clean = c2_secret_noisy - r4
    log.success("Clean ciphertexts recovered.")

    log.info("Calculating poly_result...")
    test_msg = bytes_to_long(b"This is just a test message.")
    s = (c2_test_clean * inverse_mod(test_msg, n)) % n
    poly_result = (c2_secret_clean * inverse_mod(s, n)) % n

    # --- Final Step with CRT ---
    # 1. Solve the polynomial modulo p
    log.info("Solving polynomial for m mod p...")
    Zp = GF(p)
    P_ring_p = PolynomialRing(Zp, 'm')
    mp = P_ring_p.gen()
    poly_p = sum(coeffs[i] * mp**i for i in range(e)) - poly_result
    roots_p = [int(r) for r, _ in poly_p.roots()]
    log.success(f"Found roots mod p: {roots_p}")

    # 2. Solve the polynomial modulo 100 by brute force
    log.info("Solving polynomial for m mod 100 (brute force)...")
    roots_100 = []
    for x in range(100):
        res = sum(c * pow(x, i, 100) for i, c in enumerate(coeffs))
        if (res - poly_result) % 100 == 0:
            roots_100.append(x)
    log.success(f"Found roots mod 100: {roots_100}")

    # 3. Combine with Chinese Remainder Theorem (CRT)
    log.info("Combining roots with CRT to find the flag...")
    k = 100
    for r_p in roots_p:
        for r_100 in roots_100:
            # m = crt([r_p, r_100], [p, k])
            m_final = crt([Integer(r_p), Integer(r_100)], [Integer(p), Integer(k)])
            
            try:
                flag = long_to_bytes(int(m_final))
                # CTF Flags often start with a known prefix
                if b'COMPFEST' in flag or b'flag' in flag or b'CTF' in flag:
                    log.success(f"🥳 Potential Flag Found: {flag.decode()}")
            except Exception:
                continue

if __name__ == "__main__":
    solve()