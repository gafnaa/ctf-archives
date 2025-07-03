import sys

# The name of the challenge input file
CHALL_FILE = "chall.txt"

def solve():
    """
    Reads the challenge file, calculates the result using the correct
    and efficient method, and prints the final flag.
    """
    print(f"--- CTF Challenge Solver ---")
    
    # --- 1. Read and parse the input file ---
    try:
        print(f"Reading input from '{CHALL_FILE}'...")
        with open(CHALL_FILE, 'r') as f:
            # Read the lines and remove any leading/trailing whitespace
            lines = [line.strip() for line in f.readlines()]
    except FileNotFoundError:
        print(f"\n[ERROR] The file '{CHALL_FILE}' was not found.")
        print("Please make sure the solver script is in the same directory as chall.txt.")
        return

    if len(lines) < 2:
        print(f"\n[ERROR] The file '{CHALL_FILE}' seems to be incomplete or formatted incorrectly.")
        return

    try:
        n = int(lines[0])
        a = list(map(int, lines[1].split()))
        m = 998244353
        print(f"Successfully parsed n={n} and a list of {len(a)} numbers.")
    except (ValueError, IndexError):
        print(f"\n[ERROR] Could not parse the numbers from '{CHALL_FILE}'.")
        print("Ensure the first line is one integer and the second is a space-separated list of integers.")
        return

    # --- 2. Precompute factorials modulo m ---
    # This is the most time-consuming part but is essential for large 'n'.
    print(f"Precomputing factorials up to {n} modulo {m}. This may take a moment...")
    fact = [1] * (n + 1)
    for i in range(2, n + 1):
        fact[i] = (fact[i - 1] * i) % m
    print("Factorials precomputation complete.")

    # --- 3. Define helper functions for modular arithmetic ---
    def modInverse(k):
        """Calculates the modular multiplicative inverse of k modulo m.
        This is done using Fermat's Little Theorem: k^(m-2) mod m."""
        return pow(k, m - 2, m)

    def choose(n_val, r_val):
        """
        Correctly and efficiently calculates 'n choose r' modulo m
        using the precomputed factorials.
        """
        if r_val < 0 or r_val > n_val:
            return 0
        
        # We calculate (n! * inv(r!) * inv((n-r)!)) % m
        numerator = fact[n_val]
        denominator = (fact[r_val] * fact[n_val - r_val]) % m
        
        return (numerator * modInverse(denominator)) % m

    # --- 4. Perform the main calculation ---
    print(f"Calculating the final answer by processing {len(a)} numbers...")
    ans = 1
    for i, x in enumerate(a):
        # An optional progress indicator for long lists
        if (i > 0) and (i % 50 == 0):
            print(f"  ...processed {i}/{len(a)} numbers")
            
        term = choose(n, x)
        ans = (ans * term) % m
    
    print("Calculation complete.")

    # --- 5. Print the final flag ---
    print("\n" + "="*40)
    print(f"Final Calculated Value: {ans}")
    print(f"THE FLAG IS: tjctf{{{ans}}}")
    print("="*40)


if __name__ == "__main__":
    solve()