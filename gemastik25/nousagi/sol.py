from pwn import *
import sys
import time

# --- Challenge Configuration ---
HOST = "20.6.89.33"
PORT = 8054
n = 624 # Number of rounds for MT19937
NUM_PROBE_VARS = 64 # We'll probe the first two input words (32*2 bits)

# --- GF(2) Linear Algebra Solver ---

def solve_system_gf2(A_cols, b):
    """
    Solves the system Ax = b for x in GF(2) using Gaussian elimination,
    handling non-square and singular matrices.
    A is provided as a list of columns (integers).
    b is the target vector (as an integer).
    Returns one possible solution for x if one exists, otherwise None.
    """
    num_rows = 32
    num_cols = len(A_cols)
    
    # Transpose the column matrix A_cols to a row matrix A for easier processing
    A_rows = [0] * num_rows
    for r in range(num_rows):
        for c in range(num_cols):
            if (A_cols[c] >> r) & 1:
                A_rows[r] |= (1 << c)
    
    # Create an augmented matrix [A|b]
    b_vec = [(b >> i) & 1 for i in range(num_rows)]
    
    pivot_col_indices = [-1] * num_rows
    pivot_row = 0
    for j in range(num_cols): # For each column of A
        if pivot_row == num_rows:
            break
            
        i = pivot_row
        while i < num_rows and not ((A_rows[i] >> j) & 1):
            i += 1
            
        if i < num_rows: # Found a pivot in this column at row i
            A_rows[i], A_rows[pivot_row] = A_rows[pivot_row], A_rows[i]
            b_vec[i], b_vec[pivot_row] = b_vec[pivot_row], b_vec[i]
            
            # Eliminate other 1s in this column
            for k in range(num_rows):
                if k != pivot_row and ((A_rows[k] >> j) & 1):
                    A_rows[k] ^= A_rows[pivot_row]
                    b_vec[k] ^= b_vec[pivot_row]
            
            pivot_col_indices[pivot_row] = j
            pivot_row += 1

    # Check for inconsistency (a row like [0, 0, ..., 0 | 1])
    for i in range(pivot_row, num_rows):
        if b_vec[i] == 1:
            log.error("System is inconsistent. No solution exists with these inputs.")
            return None

    # Back substitute to find one particular solution.
    # We can set all free variables (non-pivot columns) to 0.
    solution = 0
    for i in range(pivot_row - 1, -1, -1):
        pivot_col = pivot_col_indices[i]
        val = b_vec[i]
        for j in range(pivot_col + 1, num_cols):
            if (A_rows[i] >> j) & 1 and (solution >> j) & 1:
                val ^= 1
        if val:
            solution |= (1 << pivot_col)
            
    return solution


def get_rabbit_for_input(input_sequence):
    """
    Connects to the server, sends a given input sequence, and returns
    the final 'rabbit' value.
    """
    try:
        p = remote(HOST, PORT)
        p.recvuntil(b'Find the rabbit!\n')
        p.recvuntil(b'>> ')

        payload = b'\n'.join(str(num).encode() for num in input_sequence)
        p.send(payload + b'\n')

        all_output = p.recvall(timeout=10).decode()
        p.close()

        for line in reversed(all_output.strip().split('\n')):
            if "Rabbit was:" in line:
                return int(line.split(':')[1].strip())
        
        if "You found the rabbit!" in all_output:
            log.success("Found the rabbit! Here is the flag:")
            print(all_output)
            return 0 # Success

        log.warning(f"Could not find rabbit value in server output for input {input_sequence[:2]}")
        return None

    except PwnlibException as e:
        log.error(f"Connection failed during probe: {e}")
        return None
    except (ValueError, IndexError):
        log.error("Failed to parse rabbit value from server output.")
        return None


def solve():
    """
    Solves the challenge by exploiting linearity. We build a 32x64 transformation
    matrix M based on the first two input words and solve M*x = c.
    """
    log.info(f"Starting linearity attack. This will take {NUM_PROBE_VARS + 1} connections.")

    log.info(f"Probe 0/{NUM_PROBE_VARS}: Sending all zeros to find the constant c.")
    input_zeros = [0] * n
    rabbit_c = get_rabbit_for_input(input_zeros)
    if rabbit_c is None:
        log.error("Failed to get base rabbit value (c). Aborting.")
        return

    log.info(f"Constant c (rabbit for all-zero input) is: {rabbit_c}")
    
    # Build the transformation matrix M
    M = [0] * NUM_PROBE_VARS
    for k in range(NUM_PROBE_VARS):
        log.info(f"Probe {k+1}/{NUM_PROBE_VARS}: Probing to find column {k} of the matrix...")
        
        input_probe = [0] * n
        input_word_idx = k // 32
        bit_idx = k % 32
        input_probe[input_word_idx] = 1 << bit_idx

        rabbit_k = get_rabbit_for_input(input_probe)
        if rabbit_k is None:
            log.error(f"Probe for variable {k} failed. Aborting.")
            return

        # column_k = M*e_k = rabbit_k ^ c
        M[k] = rabbit_k ^ rabbit_c
        
        time.sleep(0.5)

    log.success("Successfully built the transformation matrix M.")
    
    # We want to find input `x` such that M*x = c.
    log.info("Solving the system M*x = c to find the required input...")
    
    solution_vector = solve_system_gf2(M, rabbit_c)
    
    if solution_vector is None:
        log.error("Could not solve the linear system.")
        return
        
    log.success(f"Calculated final solution vector: {solution_vector}")

    # Final attack run
    log.info("Final Attack: Sending the solution input...")
    final_input = [0] * n
    # The first 32 bits of the solution form the first input word
    final_input[0] = solution_vector & 0xFFFFFFFF
    # The next 32 bits form the second
    final_input[1] = (solution_vector >> 32) & 0xFFFFFFFF

    log.info(f"Sending input_0 = {final_input[0]}, input_1 = {final_input[1]}")
    
    try:
        p = remote(HOST, PORT)
        p.recvuntil(b'Find the rabbit!\n')
        p.recvuntil(b'>> ')

        payload = b'\n'.join(str(num).encode() for num in final_input)
        p.send(payload + b'\n')

        final_output = p.recvall(timeout=10).decode()
        p.close()
        
        log.success("Final attack sent. Server response:")
        print("="*50)
        print(final_output.strip())
        print("="*50)

    except PwnlibException as e:
        log.error(f"Connection failed during final attack: {e}")


if __name__ == "__main__":
    context.log_level = 'info'
    solve()

