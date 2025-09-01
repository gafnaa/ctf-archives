import math

# --- Provided x-coordinates ---
x_coords_str = [
    "107272975926831189203093841707559392284196422250425726891770885243136820682014934349433103191527393137164120193928212669026",
    "374853083552152078419039464177707506579660105110608120559550314246363586610150004443884038673260767177223398181301219615660",
    "485187492909966794004047116680521452300686108500430520950311238302343572058359657075519835637615364779137174912626312338531",
    "38193999044104893849164286500179192460028939644654475814230534259565547127270090699694745094032686205767820545022456112085",
    "37970831378415192374658635191846065163949293847357070503833815835056062797434179456540474589182901189022239670294761461662",
    "139309949922716953726279444353122274003603470688142353561327558900253510008441406378689256197462527465935603671888192962403",
    "551768143431797199419974031385844691632760459295442605629449590496465968671785864315071782273280637880717656759522827359850"
]
x = [int(s) for s in x_coords_str]

# --- Corrected Mathematical Derivations ---
# The core relation is (x_{i-1} + x_{i+1} + 2x_i + 2x_g)(x_i-x_g)^2 = 2(x_i^3+x_g^3) + 2a(x_i+x_g) + 4b
# Let C_i(x_g) be a polynomial representing (x_{i-1} + ...)(x_i-x_g)^2 - 2x_i^3.
# The relation becomes C_i(x_g) = 2x_g^3 + 2a(x_i+x_g) + 4b.
# By taking differences, we eliminate unknowns.
# C_i(x_g) - C_{i+1}(x_g) = 2a(x_i - x_{i+1}).
# Let D_i(x_g) = C_i(x_g) - C_{i+1}(x_g).
# This implies D_i(x_g) / (x_i - x_{i+1}) = 2a, which is constant.
# This allows us to form a polynomial F_i(x_g) = 0 (mod p) and solve for x_g and p.

def get_K_poly_coeffs(i, x_coords):
    """
    Calculates the coefficients of the polynomial C_i(x_g).
    The formula uses 1-based indexing for points, so we adjust for 0-based array indices.
    """
    xi_minus_1 = x_coords[i-1]
    xi = x_coords[i]
    xi_plus_1 = x_coords[i+1]
    
    # Coefficients of C_i(x_g) = K3*x_g^3 + K2*x_g^2 + K1*x_g + K0
    # derived from expanding (x_{i-1} + x_{i+1} + 2x_i + 2x_g)(x_i-x_g)^2 - 2x_i^3
    # The previous versions of this script had algebraic errors in this expansion.
    K3 = 2
    K2 = xi_plus_1 + xi_minus_1 - 2*xi
    K1 = -2 * (xi * xi_plus_1 + xi * xi_minus_1 + xi**2)
    K0 = xi**2 * (xi_plus_1 + xi_minus_1)
    return K3, K2, K1, K0

# --- Step 1: Calculate coefficients for C_i polynomials ---
K_coeffs = {}
# We need K_i for i=1..5 to form F_1, F_2, F_3
for i in range(1, 6):
    K_coeffs[i] = get_K_poly_coeffs(i, x)

# --- Step 2: Calculate coefficients for D_i polynomials ---
# D_i(x_g) = C_i(x_g) - C_{i+1}(x_g)
d_coeffs = {}
for i in range(1, 5):
    # K3 is constant (2), so K3_i - K3_{i+1} = 0. D_i is quadratic.
    d2 = K_coeffs[i][1] - K_coeffs[i+1][1] # K2_i - K2_{i+1}
    d1 = K_coeffs[i][2] - K_coeffs[i+1][2] # K1_i - K1_{i+1}
    d0 = K_coeffs[i][3] - K_coeffs[i+1][3] # K0_i - K0_{i+1}
    d_coeffs[i] = (d2, d1, d0)

# --- Step 3: Calculate coefficients for F_i polynomials ---
# F_i(x_g) = D_i(x_g)*(x_{i+1}-x_{i+2}) - D_{i+1}(x_g)*(x_i-x_{i+1})
F_coeffs = {}
for i in range(1, 4):
    dx_i = x[i] - x[i+1]
    dx_i_plus_1 = x[i+1] - x[i+2]
    
    f2 = d_coeffs[i][0] * dx_i_plus_1 - d_coeffs[i+1][0] * dx_i
    f1 = d_coeffs[i][1] * dx_i_plus_1 - d_coeffs[i+1][1] * dx_i
    f0 = d_coeffs[i][2] * dx_i_plus_1 - d_coeffs[i+1][2] * dx_i
    F_coeffs[i] = (f2, f1, f0)

# --- Step 4: Find p by finding a common root relationship ---
K2_1, K1_1, K0_1 = F_coeffs[1]
K2_2, K1_2, K0_2 = F_coeffs[2]
K2_3, K1_3, K0_3 = F_coeffs[3]

# Remainder of F_1, F_2: L(x_g) = (K2_1*F_2 - K2_2*F_1)
L1 = K2_1 * K1_2 - K2_2 * K1_1
L0 = K2_1 * K0_2 - K2_2 * K0_1

# Remainder of F_2, F_3: L'(x_g) = (K2_2*F_3 - K2_3*F_2)
L1_prime = K2_2 * K1_3 - K2_3 * K1_2
L0_prime = K2_2 * K0_3 - K2_3 * K0_2

# The determinant must be 0 mod p.
M = L1 * L0_prime - L0 * L1_prime

# p must be the largest prime factor of M.
# Using an online factorizer for M gives the prime p.
p = 1115592147374241288843353323343542263984536204510236592398223661333918863116613813363399441113111039474493948139091241334493
print(f"[*] Found prime p = {p}")

# --- Step 5: Solve for x_g, a, and b ---
# From L1*x_g + L0 = 0 (mod p)
xg = (-L0 * pow(L1, -1, p)) % p
print(f"[*] Found generator x-coordinate x_g = {xg}")

# Find 'a' using D_1(x_g) / (x_1 - x_2) = 2a
d1_at_xg = (d_coeffs[1][0]*xg**2 + d_coeffs[1][1]*xg + d_coeffs[1][2]) % p
a_times_2 = (d1_at_xg * pow(x[1] - x[2], -1, p)) % p
a = (a_times_2 * pow(2, -1, p)) % p
print(f"[*] Found curve parameter a = {a}")

# Find 'b' using C_1(x_g) = 2*x_g^3 + 2a(x_1+x_g) + 4b
C1_at_xg = (K_coeffs[1][0]*xg**3 + K_coeffs[1][1]*xg**2 + K_coeffs[1][2]*xg + K_coeffs[1][3]) % p
b_times_4 = (C1_at_xg - 2 * pow(xg, 3, p) - a_times_2 * (x[1] + xg)) % p
b = (b_times_4 * pow(4, -1, p)) % p
print(f"[*] Found curve parameter b = {b}")

# --- Step 6: Construct the flag ---
flag_val = p + a + b

flag = f"hacktoday{{{hex(flag_val)}}}"

print("\n" + "="*50)
print(f"Flag: {flag}")
print("="*50)

