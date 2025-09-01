# This script must be run in a SageMath environment.
# You will also need to install the z3-solver library:
# sage -pip install z3-solver

from sage.all import *
# Reverted to the standard wildcard import for z3, which is the most common usage.
# If this fails, it indicates a problem with the z3-solver installation itself.
from z3 import *
from Crypto.Util.number import long_to_bytes

# --- Parse A_values and b_values from out.txt ---
try:
    with open('out.txt', 'r') as f:
        # The file content is Python code, so we can execute it
        # to define the A_values and b_values variables.
        file_content = f.read()
        # Pass globals() to exec to ensure variables are in the global scope
        exec(file_content, globals())
    print("[+] Successfully parsed A_values and b_values from out.txt")
except FileNotFoundError:
    print("[!] Error: out.txt not found. Please make sure the file is in the same directory.")
    exit()
except Exception as e:
    print(f"[!] An error occurred while parsing out.txt: {e}")
    exit()
# --- End of parsing section ---


# 1. Setup constants and finite field
mod = 0x225fd
e_values = [97491, 14061, 55776] 
F = GF(mod)

# 2. Create matrices and vectors
# The A_values and b_values are now loaded from the file
A_mat = matrix(F, 52, 44, [item for row in A_values for item in row])
# Corrected the creation of b_vec to handle a flat list of integers
b_vec = vector(F, b_values)

# 3. Find the left kernel of the matrix A
# This gives us a basis for the space of vectors c such that c*A = 0
print("[+] Finding left kernel of A...")
C_basis_mat = A_mat.left_kernel().basis_matrix()
print(f"[+] Found kernel with dimension: {C_basis_mat.nrows()}")

# 4. Use LLL to find a basis of short vectors for the kernel lattice
print("[+] Applying LLL algorithm to find a short basis...")
C_int_mat = C_basis_mat.change_ring(ZZ)
C_reduced_int = C_int_mat.LLL()

# 5. Define the error structure
# The errors are in an arithmetic progression: e_2, e_3, e_1
# e_values sorted: [14061, 55776, 97491]
e_base = 14061
delta = 55776 - 14061 # 41715

# 6. Transform the system of equations
# We have c*b = c*e. Let e_i = e_base + k_i*delta, where k_i in {0,1,2}
# c*b = c*(e_base_vec + k*delta) => (c*b - e_base*c*vec(1)) * delta^-1 = c*k
print("[+] Transforming system of equations...")
C_reduced_F = C_reduced_int.change_ring(F)
d_vec = C_reduced_F * b_vec
sum_c_vec = C_reduced_F * vector(F, [1]*52)
d_prime_vec = d_vec - e_base * sum_c_vec
# Corrected exponentiation operator from ^ to **
delta_inv = F(delta)**-1
d_double_prime_vec = d_prime_vec * delta_inv

# 7. Use Z3 SMT solver to find the vector k
print("[+] Solving for k vector with Z3...")
# Z3 functions are now in the global namespace from the wildcard import
solver = Solver()
k = [Int(f'k_{i}') for i in range(52)]

# Add constraints: 0 <= k_i <= 2
for i in range(52):
    solver.add(k[i] >= 0)
    solver.add(k[i] <= 2)

# Add the 8 modular linear equations: C_reduced * k = d_double_prime (mod p)
# This approach is more robust as it doesn't require the LLL basis to be
# exceptionally short. It lets the SMT solver handle the modular arithmetic.
print("[+] Adding modular constraints to Z3 solver...")
for j in range(C_reduced_int.nrows()):
    # The integer linear combination on the left-hand side
    equation_lhs = Sum([C_reduced_int[j, i] * k[i] for i in range(52)])
    
    # The expected result in the finite field (right-hand side)
    d_val = Integer(d_double_prime_vec[j])
    
    # The constraint that the integer sum must be congruent to d_val modulo mod
    solver.add(equation_lhs % mod == d_val)

# 8. Check for a solution and reconstruct the flag
if solver.check() == sat:
    print("[+] Z3 found a solution for k!")
    model = solver.model()
    k_solution = [model.evaluate(k[i]).as_long() for i in range(52)]
    
    # 9. Reconstruct the flag
    # Calculate the error vector e from the k solution
    e_solution = [e_base + ki * delta for ki in k_solution]
    
    # Take the first 44 equations to solve for S
    A_solve = A_mat.submatrix(0, 0, 44, 44)
    b_solve = b_vec.subvector(0, 44)
    e_solve_vec = vector(F, e_solution[:44])
    
    # Ensure the matrix is invertible
    if A_solve.rank() == 44:
        # Solve A*S = b - e
        S = A_solve.solve_right(b_solve - e_solve_vec)
        
        # Reconstruct the flag from its base-mod representation
        flag_long = 0
        for i in range(44):
            flag_long += Integer(S[i]) * (mod**i)
            
        flag_bytes = long_to_bytes(flag_long)
        print("\n" + "="*40)
        print(f"🎉 Flag Found: {flag_bytes.decode()}")
        print("="*40)
    else:
        print("[!] Error: Submatrix is not invertible. Cannot solve for S.")
else:
    print("[!] Z3 failed to find a solution.")
