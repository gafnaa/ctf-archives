# Save this as decrypt.py and run it with `sage decrypt.py`

from Crypto.Util.number import long_to_bytes
import ast
from sage.all import EllipticCurve, GF

def solve():
    """
    Definitive decryptor that prunes the search space at each byte boundary
    to find the single, meaningful ASCII flag.
    """
    # BLS12-381 curve parameters
    p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
    K = GF(p)
    E = EllipticCurve(K, (0, 4))

    # --- Read and parse the challenge file ---
    challenge_points_coords = []
    try:
        with open("chall.txt", "r") as f:
            challenge_points_coords = ast.literal_eval(f.read())
    except Exception as e:
        print(f"[-] Error reading or parsing chall.txt: {e}")
        return

    bit_length = len(challenge_points_coords)
    print(f"[+] Loaded {bit_length} points from challenge.")

    # --- Beam Search / Pruning DP ---
    # dp[i] maps a state z_i to a list of valid path *prefixes* of length i.
    # At each byte boundary, we prune paths that don't form printable ASCII.
    
    # The state z_i is 1 if t_i=0, and 0 otherwise.
    dp = [{} for _ in range(bit_length + 1)]
    dp[0] = {
        0: [""],  # Represents initial state t_0 in {1, 2}
        1: [""]   # Represents initial state t_0 = 0
    }

    print("[*] Starting constrained search...")
    for i in range(bit_length):
        if not dp[i]:
            print("[-] Search space exhausted. No solution found.")
            return

        dp_next = {0: [], 1: []}
        
        # Iterate through current valid states and their path prefixes
        for z_i, prefixes in dp[i].items():
            for p in prefixes:
                # Case c_i = '0'
                # Implies t_{i+1} = 0, so z_{i+1} = 1.
                dp_next[1].append(p + '0')

                # Case c_i = '1'
                # Requires t_i = 0, so z_i = 1.
                if z_i == 1:
                    # t_{i+1} is unconstrained, so z_{i+1} can be 0 or 1.
                    dp_next[0].append(p + '1')
                    dp_next[1].append(p + '1')

        dp[i+1] = dp_next

        # Pruning step at each byte boundary
        if (i + 1) % 8 == 0:
            char_num = (i + 1) // 8
            print(f"[*] Pruning after character {char_num}...")
            
            pruned_dp = {0: [], 1: []}
            for z_val, prefixes in dp[i+1].items():
                for p in prefixes:
                    last_byte_str = p[-8:]
                    byte_val = int(last_byte_str, 2)
                    
                    # Keep only paths that form a printable ASCII character
                    if 32 <= byte_val <= 126:
                        pruned_dp[z_val].append(p)
            dp[i+1] = pruned_dp
            
            # Log how many valid paths remain
            total_paths = sum(len(paths) for paths in dp[i+1].values())
            print(f"    {total_paths} valid path(s) remain.")


    print("[+] Search complete.")

    # --- Extract the final flag ---
    final_paths = []
    for z_val, prefixes in dp[bit_length].items():
        final_paths.extend(prefixes)
    
    if not final_paths:
        print("[-] No valid flag found after full search.")
        return
        
    print(f"\n[+] Found {len(final_paths)} possible flag(s):")
    for b_flag in final_paths:
        try:
            flag_num = int(b_flag, 2)
            flag = long_to_bytes(flag_num, bit_length // 8)
            print(f"  -> {flag.decode()}")
        except Exception as e:
            print(f"  -> {b_flag} (Could not decode: {e})")


if __name__ == "__main__":
    solve()