#!/usr/bin/env python3

import pwn
from Crypto.Util.number import inverse

# The constant from the challenge script
K = 0xD3ADC0DE

def get_x(secret_guess, inv_g, n_sq):
    """
    Calculates x = g^-(secret_guess + K) mod n^2.
    """
    exponent = secret_guess + K
    return pow(inv_g, exponent, n_sq)

def to_base3(n, pad=7):
    """
    Converts an integer to its base-3 representation as a list of trits.
    """
    if n == 0: return [0] * pad
    nums = []
    while n:
        n, r = divmod(n, 3)
        nums.append(r)
    # Pad with leading zeros to ensure consistent length
    return (nums + [0] * pad)[:pad]

def solve():
    """
    Connects to the server and solves the challenge non-adaptively.
    """
    p = pwn.remote("0.cloud.chals.io", 32957)

    for i in range(10):
        print(f"--- Solving Test #{i+1} ---")
        p.recvuntil(b"--- Test #")
        p.recvline()

        line = p.recvline().decode().strip()
        n = int(line.split(" = ")[1])
        
        # We must read this line before preparing queries
        p.recvuntil(b"You can ask 7 questions:\n")

        g = n + 1
        n_sq = n * n
        inv_g = inverse(g, n_sq)

        # --- 1. Prepare all 7 queries in advance ---
        all_queries = []
        for i in range(7):  # For each of the 7 trits
            part0_secrets = []  # Secrets where the i-th trit is 0
            part1_secrets = []  # Secrets where the i-th trit is 1

            for s in range(2048):
                trits = to_base3(s, pad=7)
                if trits[i] == 0:
                    part0_secrets.append(s)
                elif trits[i] == 1:
                    part1_secrets.append(s)

            xs0 = [get_x(s, inv_g, n_sq) for s in part0_secrets]
            xs1 = [get_x(s, inv_g, n_sq) for s in part1_secrets]

            # The server splits the list exactly in half. For our logic to work,
            # the left half must be xs0 and the right half xs1.
            # Therefore, they MUST have the same length. We pad the shorter list.
            if len(xs0) > len(xs1):
                padding = [get_x(s + 2048, inv_g, n_sq) for s in range(len(xs0) - len(xs1))]
                xs1.extend(padding)
            elif len(xs1) > len(xs0):
                padding = [get_x(s + 2048, inv_g, n_sq) for s in range(len(xs1) - len(xs0))]
                xs0.extend(padding)
            
            query_list = xs0 + xs1
            all_queries.append(" ".join(map(str, query_list)))

        # --- 2. Send all queries ---
        for q_str in all_queries:
            p.sendline(q_str.encode())

        # --- 3. Receive all results ---
        results = []
        for _ in range(7):
            res_line = p.recvline().decode().strip()
            l_res, r_res = map(int, res_line.split())
            results.append((l_res, r_res))

        # --- 4. Reconstruct the secret ---
        secret_trits = [0] * 7
        for i in range(7):
            l_res, r_res = results[i]
            if l_res == 0:
                secret_trits[i] = 0
            elif r_res == 0:
                secret_trits[i] = 1
            else:
                secret_trits[i] = 2

        secret = 0
        power_of_3 = 1
        for trit in secret_trits:
            secret += trit * power_of_3
            power_of_3 *= 3

        print(f"Secret found: {secret}")
        p.sendline(str(secret).encode())
        print(p.recvline().decode().strip())

    # (at the end of the solve function)
    # After the final "Correct!" is printed, read everything else the
    # server sends until the connection closes. This is more robust.
    remaining_output = p.recvall(timeout=2).decode()
    print(remaining_output.strip())
    p.close()

if __name__ == '__main__':
    solve()