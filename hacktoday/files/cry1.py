

# This script solves a system of subset sum problems using the LLL algorithm.
# It is designed to decrypt the output from the provided encryption script.
# This version uses the 'fpylll' library instead of SageMath.
#
# HOW TO RUN:
# 1. Make sure you have Python 3 installed.
# 2. Install the required library: pip install fpylll
# 3. Save this script as `decrypt.py`.
# 4. Place the `output.txt` file in the same directory.
# 5. Run the script from your terminal: python decrypt.py

import ast
import sys

try:
    from fpylll import IntegerMatrix, LLL
except ImportError:
    print("[ERROR] The 'fpylll' library is not installed.")
    print("Please install it by running: pip install fpylll")
    sys.exit(1)

def long_to_bytes(n):
    """
    Converts a long integer back to a byte string.
    """
    if n == 0:
        return b'\x00'
    # Calculate the number of bytes needed and convert
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')

def parse_output_file(filename="output.txt"):
    """
    Parses the output.txt file to extract the public values and sums.
    """
    try:
        with open(filename, "r") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] The file '{filename}' was not found.")
        print("Please ensure the output file is in the same directory as this script.")
        sys.exit(1)

    public_values = []
    sums = []
    
    # Use a simple state machine to parse the file
    parsing_mode = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if "Public values:" in line:
            parsing_mode = 'public'
            continue
        elif "Sums:" in line:
            parsing_mode = 'sums'
            continue

        if parsing_mode == 'public':
            try:
                # Extracts the list part of the string "Public values X: [...]"
                list_str = line.split(":", 1)[1].strip()
                public_values.append(ast.literal_eval(list_str))
            except (ValueError, SyntaxError) as e:
                print(f"[ERROR] Failed to parse public values line: {line}")
                print(f"Error: {e}")
                sys.exit(1)
        elif parsing_mode == 'sums':
            try:
                # Extracts the number part of the string "Sum X: ..."
                sum_val_str = line.split(":", 1)[1].strip()
                sums.append(int(sum_val_str))
            except ValueError as e:
                print(f"[ERROR] Failed to parse sums line: {line}")
                print(f"Error: {e}")
                sys.exit(1)
                
    if not public_values or not sums:
        print("[ERROR] Could not parse public values or sums from the file. The file might be empty or malformed.")
        sys.exit(1)
        
    return public_values, sums

def solve_subset_sum_system(public, sums):
    """
    Constructs the lattice and uses LLL to find the secret coefficients.
    """
    num_equations = len(sums)
    if not num_equations:
        print("[ERROR] No sums provided.")
        return None
        
    num_unknowns = len(public[0])
    
    print(f"[*] Found {num_equations} equations with {num_unknowns} unknowns.")
    
    # Construct the (n+m) x (n+m) basis matrix M for the lattice.
    # The matrix M is:
    # [ I_n | P^T   ]
    # [ --- | ----- ]
    # [  0  | -S_diag ]
    
    matrix_size = num_unknowns + num_equations
    
    print("[*] Constructing the lattice basis matrix...")

    # Create the matrix as a list of lists first
    M_list = [[0] * matrix_size for _ in range(matrix_size)]

    # Fill the matrix according to the structure
    for i in range(num_unknowns):
        M_list[i][i] = 1
        for j in range(num_equations):
            M_list[i][num_unknowns + j] = public[j][i]

    for i in range(num_equations):
        M_list[num_unknowns + i][num_unknowns + i] = -sums[i]
        
    # Convert the list of lists to an fpylll IntegerMatrix
    M = IntegerMatrix.from_matrix(M_list)

    print("[*] Running the LLL algorithm... (This may take a moment)")
    
    # Run the LLL algorithm. This modifies the matrix M in-place.
    LLL.reduction(M)
    
    print("[*] LLL finished. Analyzing the results...")

    # The first vector in the reduced basis should be our solution vector.
    solution_vector = M[0]
    
    # Extract the coefficients (the first n elements)
    # Take absolute value as LLL might find the negative of the vector.
    # We must access elements by index, as fpylll rows don't support slicing.
    coeffs = [abs(round(solution_vector[i])) for i in range(num_unknowns)]
    
    # Sanity check: ensure the remaining elements are all zero
    for i in range(num_equations):
        if solution_vector[num_unknowns + i] != 0:
            print("[ERROR] LLL reduction likely failed.")
            print("The resulting vector does not have the expected form.")
            return None

    # Sanity check: ensure coefficients are binary
    if any(c not in [0, 1] for c in coeffs):
        print("[WARNING] The solution found is not binary. The result might be incorrect.")
        print(f"Found coefficients: {coeffs}")

    return coeffs


if __name__ == "__main__":
    print("--- Subset Sum System Decryptor (using fpylll) ---")
    
    # 1. Parse the input file
    public_data, sums_data = parse_output_file()
    
    # 2. Solve the system using LLL
    secret_coeffs = solve_subset_sum_system(public_data, sums_data)
    
    if secret_coeffs:
        # 3. Convert coefficients back to the flag
        print("[*] Converting binary coefficients back to flag...")
        try:
            binary_flag_str = "".join(map(str, secret_coeffs))
            flag_integer = int(binary_flag_str, 2)
            flag_bytes = long_to_bytes(flag_integer)
        
            print("\n" + "="*40)
            print("🎉 Decryption Successful! 🎉")
            print(f"[*] Flag: {flag_bytes.decode('utf-8', errors='ignore')}")
            print("="*40)
        except Exception as e:
            print(f"[ERROR] Failed to convert the result to a flag: {e}")
            print(f"[*] Raw binary string: {binary_flag_str}")
