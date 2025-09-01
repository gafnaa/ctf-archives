from sage.all import *
import ast

def solve():
    print("Step 1: Loading constants and data from out.txt...")
    mod = 0x225fd
    e_values = [97491, 14061, 55776]

    try:
        with open('out.txt', 'r') as f:
            content = f.read().strip()
        part1, part2 = content.split(';')
        A_str = part1.split('=', 1)[1].strip()
        b_str = part2.split('=', 1)[1].strip()
        A_raw = ast.literal_eval(A_str)
        b_raw = ast.literal_eval(b_str)
        print("Data loaded successfully.")
    except Exception as e:
        print(f"Error reading or parsing out.txt: {e}")
        return

    # --- 2. Setup SageMath Mathematical Structures ---
    print("Step 2: Setting up matrices over the finite field GF({})...".format(mod))
    F = GF(mod)
    # The matrix A has 52 rows (samples) and 44 columns (dimensions)
    A = Matrix(F, A_raw)
    # b is the vector of results
    b = vector(F, b_raw)

    print("Step 3: Calculating the left kernel of matrix A to eliminate the secret S...")
    K = A.left_kernel()
    if K.dimension() == 0:
        print("Error: The left kernel is empty. This attack method won't work.")
        return
    c = K.basis()[0] # We only need one non-zero vector from the kernel
    print("Kernel vector `c` found.")

    # Calculate the target sum T for our knapsack-like problem
    T = c * b
    print(f"Target sum T calculated: {T}")

    print("Step 4: Using dynamic programming to determine the error vector `e`...")
    dp_stages = []
    # Initial state: a sum of 0 is reachable with no elements.
    dp = {F(0): (None, -1)}
    dp_stages.append(dp)

    for i in range(52):
        next_dp = {}
        ci = c[i]
        for prev_sum in dp:
            for j, err in enumerate(e_values):
                current_sum = prev_sum + ci * F(err)

                if current_sum not in next_dp:
                    next_dp[current_sum] = (prev_sum, j)
        dp = next_dp
        dp_stages.append(dp)
        if (i + 1) % 10 == 0:
            print(f"  DP stage {i+1}/52 complete. Table size: {len(dp)}")

    print("DP calculation finished.")


    print("Step 5: Backtracking through the DP table to find the exact error vector...")
    e = [0] * 52
    current_T = T

    if current_T not in dp_stages[52]:
        print("Error: Target sum T was not found in the final DP table. Decryption failed.")
        return

    # Trace back from the final stage to find the path (which errors were chosen)
    for i in range(51, -1, -1):
        prev_sum, err_idx = dp_stages[i+1][current_T]
        e[i] = e_values[err_idx]
        current_T = prev_sum
    print("Error vector `e` successfully reconstructed.")


    print("Step 6: Solving the linear system for the secret vector S...")
    A_prime = A.matrix_from_rows(range(44))
    b_prime_list = [(b[i] - F(e[i])) for i in range(44)]
    b_prime = vector(F, b_prime_list)

    try:
        S = A_prime.solve_right(b_prime)
        print("Secret vector S found.")
    except Exception as ex:
        print(f"Could not solve for S. The matrix may be singular. Error: {ex}")
        return


    print("Step 7: Reconstructing the flag from the secret vector S...")
    

    S_list_int = [Integer(s_val) for s_val in S]
    
    flag_long = 0

    for s_val in reversed(S_list_int):
        flag_long = flag_long * mod + s_val

    try:
       
        num_bytes = (flag_long.nbits() + 7) // 8
        flag_bytes = flag_long.to_bytes(num_bytes, 'big')
        print("\n" + "="*40)
        print(f"DECRYPTION SUCCESSFUL!")
        try:

            print(f"Flag: {flag_bytes.decode()}")
        except UnicodeDecodeError:
      
            print("Flag (raw bytes, could not decode as UTF-8):")
            print(flag_bytes)
        print("="*40)
        return flag_bytes
    except Exception as ex:
        print(f"Failed to convert number to bytes. Error: {ex}")


if __name__ == "__main__":
    solve()

