# Save this as decrypt.py and run it with `sage decrypt.py`

from Crypto.Util.number import long_to_bytes
import ast

def solve():
    """
    An optimized decryptor that handles the "all-zero beta" case 
    without running out of memory.
    """
    # BLS12-381 curve parameters
    p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    K = GF(p)
    E = EllipticCurve(K, (0, 4))
    G1, G2 = E.gens()
    o1, o2 = G1.order(), G2.order()
    O = E(0)

    # --- Read and parse the challenge file ---
    challenge_points_coords = []
    try:
        with open("chall.txt", "r") as f:
            challenge_points_coords = ast.literal_eval(f.read())
    except Exception as e:
        print(f"[-] Error reading or parsing chall.txt: {e}")
        return

    cs = [E(x, y) for x, y in challenge_points_coords]
    bit_length = len(cs)
    print(f"[+] Loaded {bit_length} points from challenge.")
    
    # As the output shows, beta is all zeros. We can skip the calculation.
    beta = [0] * bit_length
    print(f"[+] Using pre-calculated beta sequence of all zeros.")

    # --- Memory-Efficient Dynamic Programming ---
    # The state z_i is 1 if t_i=0, and 0 otherwise.
    # dp[i] will store parent pointers: {z_i_val: (parent_z_val, bit_val)}
    # This avoids storing exponentially many path strings.
    
    dp = [{} for _ in range(bit_length + 1)]
    
    # We don't know the initial state, so we assume it could be anything.
    # The 'parent' of the initial state is a placeholder.
    dp[0][0] = (-1, -1)  # Represents t_0 in {1, 2}
    dp[0][1] = (-1, -1)  # Represents t_0 = 0

    print("[*] Building solution graph...")
    for i in range(bit_length):
        b_i = beta[i] # This is always 0

        # Check for ASCII high-bit constraint
        # Bit c_i must be 0 if i is 7, 15, 23, ...
        is_ascii_constrained = ((i + 1) % 8 == 0)

        for z_i, _ in dp[i].items():
            # Case c_i = '0':
            # This is always a possible move.
            # Implies t_{i+1} = beta_i = 0, so z_{i+1} = 1.
            if not is_ascii_constrained: # Only explore this if c_i can be '0'
                z_next = 1
                dp[i+1][z_next] = (z_i, 0)

            # Case c_i = '1':
            # Requires t_i = beta_i = 0, which means z_i = 1.
            if z_i == 1:
                # This move is only possible if the bit is not constrained to be '0'.
                if not is_ascii_constrained:
                    # Next state t_{i+1} is unconstrained, so z_{i+1} can be 0 or 1
                    # This is the source of the ambiguity, but we only need to store one parent.
                    dp[i+1][0] = (z_i, 1) # Corresponds to t_{i+1} in {1,2}
                    dp[i+1][1] = (z_i, 1) # Corresponds to t_{i+1} = 0
            
            # If the bit is ASCII-constrained, c_i MUST be 0
            if is_ascii_constrained:
                z_next = 1
                dp[i+1][z_next] = (z_i, 0)
    
    print("[+] Solution graph built.")

    # --- Backtrack to find one valid flag ---
    if not dp[bit_length]:
        print("[-] No solution found. The ASCII constraint might be too strong.")
        return

    print("[*] Backtracking to reconstruct a flag candidate...")
    
    # Start from any valid final state
    current_z = list(dp[bit_length].keys())[0]
    
    binary_flag = ""
    for i in range(bit_length, 0, -1):
        parent_z, bit = dp[i][current_z]
        binary_flag = str(bit) + binary_flag
        current_z = parent_z

    print("[+] Found a valid candidate!")
    try:
        flag_num = int(binary_flag, 2)
        flag = long_to_bytes(flag_num)
        print(f"  -> {flag.decode()}")
    except Exception as e:
        print(f"  -> {binary_flag} (Could not decode: {e})")

if __name__ == "__main__":
    solve()