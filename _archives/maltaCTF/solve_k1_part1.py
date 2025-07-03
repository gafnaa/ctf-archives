import math

print("Starting solve_k1_part1.py - Debugging...")

# Given values
h2 = int(6525529513224929513242286153522039835677193513612437958976590021494532059727)
h3 = int(42423271339336624024407863370989392004524790041279794366407913985192411875865)

# Modulus
p = int(2**255 - 19)
print(f"p = {p}")

# Initial matrix G
G_initial_vals = [[1401, 2], [-2048, 1273]]
a = int(G_initial_vals[0][0])
b = int(G_initial_vals[0][1])
c = int(G_initial_vals[1][0])
d = int(G_initial_vals[1][1])

print(f"a={a}, b={b}, c={c}, d={d}")

# Helper for modular inverse
def mod_inverse(val, mod):
    # Python's pow(base, -1, mod) works for modular inverse
    return pow(val, -1, mod)

print("Calculating b_inv...")
b_inv = mod_inverse(b, p)
print(f"b_inv = {b_inv}")

print("Calculating c1 and c0...")
c1 = (h3 * b_inv) % p
c0 = (h2 - c1 * a) % p
print(f"c1 = {c1}")
print(f"c0 = {c0}")

print("Calculating trace and determinant...")
tr = (a + d) % p
dt = (a * d - b * c) % p
print(f"tr = {tr}")
print(f"dt = {dt}")

# Hardcoded eigenvalues from solve_k1.sage
lambda1 = int(1342)
lambda2 = int(1332)
print(f"lambda1 = {lambda1}")
print(f"lambda2 = {lambda2}")

print("Calculating X_target and Y_target...")
X_target = (c0 + c1 * lambda1) % p
Y_target = (c0 + c1 * lambda2) % p

print(f"X_target = {X_target}")
print(f"Y_target = {Y_target}")

print("Script finished successfully.")
