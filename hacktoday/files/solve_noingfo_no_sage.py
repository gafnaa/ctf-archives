import math
import random

# ==============================================================================
# Part 1: Mathematical Primitives
# ==============================================================================

def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n < 2: return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if n == p: return True
        if n % p == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# ==============================================================================
# Part 2: Main Attack Logic
# ==============================================================================

# These are the 7 x-coordinates provided in the challenge.
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

def get_C_poly_coeffs(i, x_coords):
    """
    Calculates the coefficients of the polynomial C_i(x_g).
    The formula is derived from the relation between x-coordinates of 3 consecutive points.
    C_i(x_g) = (x_{i-1} + x_{i+1} + 2x_i + 2x_g)(x_i-x_g)^2 - 2x_i^3
    """
    xi_minus_1 = x_coords[i-1]
    xi = x_coords[i]
    xi_plus_1 = x_coords[i+1]
    
    # Coefficients of C_i(x_g) = K3*x_g^3 + K2*x_g^2 + K1*x_g + K0
    K3 = 2
    K2 = xi_plus_1 + xi_minus_1 - 2*xi
    K1 = -2 * (xi * xi_plus_1 + xi * xi_minus_1 + xi**2)
    K0 = xi**2 * (xi_plus_1 + xi_minus_1)
    return K3, K2, K1, K0

def calculate_p_invariant(coords):
    """Calculates a robust invariant using 5 consecutive points."""
    x0, x1, x2, x3, x4 = [int(c) for c in coords]
    S0 = x1 - x0
    S1 = x2 - x1
    S2 = x3 - x2
    S3 = x4 - x3
    D0 = x1 + x0
    D1 = x2 + x1
    D2 = x3 + x2
    D3 = x4 + x3
    LHS = (((S1 * S3 - S0 * S2)**2 - (S1 + S3) * (S0 + S2) * S1 * S3)) * (D0 - D2)
    RHS = (((S0 * S3 - S1 * S2)**2 - (S0 + S3) * (S1 + S2) * S0 * S3)) * (D1 - D3)
    return LHS - RHS

# --- Step 1: Recover the prime p ---
print("Step 1: Recovering the prime p...")

# The GCD of the invariants should be a multiple of p.
K1 = calculate_p_invariant(x[0:5])
K2 = calculate_p_invariant(x[1:6])
K3 = calculate_p_invariant(x[2:7])

p_candidate = abs(math.gcd(K1, math.gcd(K2, K3)))

# The GCD might be k*p. We divide out small prime factors to isolate p.
for small_prime in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53]:
    while p_candidate > small_prime and p_candidate % small_prime == 0:
        p_candidate //= small_prime

p = p_candidate
print(f"Found candidate for p = {p}")

if not is_prime(p):
    print("\nFailed to recover a valid prime. The candidate is not prime. Exiting.")
    exit()

# --- Step 2: Solve for x_g, a, and b ---
print("\nStep 2: Recovering curve parameters...")

# Calculate coefficients for C_i polynomials over the integers
C_coeffs = {}
for i in range(1, 6): # We need C_i for i=1..5
    C_coeffs[i] = get_C_poly_coeffs(i, x)

# Calculate coefficients for D_i(x_g) = C_i(x_g) - C_{i+1}(x_g)
d_coeffs = {}
for i in range(1, 5):
    d2 = C_coeffs[i][1] - C_coeffs[i+1][1]
    d1 = C_coeffs[i][2] - C_coeffs[i+1][2]
    d0 = C_coeffs[i][3] - C_coeffs[i+1][3]
    d_coeffs[i] = (d2, d1, d0)

# Calculate coefficients for F_i(x_g) = D_i(x_g)*(x_{i+1}-x_{i+2}) - D_{i+1}(x_g)*(x_i-x_{i+1})
F_coeffs = {}
for i in range(1, 4):
    dx_i = x[i] - x[i+1]
    dx_i_plus_1 = x[i+1] - x[i+2]
    
    f2 = d_coeffs[i][0] * dx_i_plus_1 - d_coeffs[i+1][0] * dx_i
    f1 = d_coeffs[i][1] * dx_i_plus_1 - d_coeffs[i+1][1] * dx_i
    f0 = d_coeffs[i][2] * dx_i_plus_1 - d_coeffs[i+1][2] * dx_i
    F_coeffs[i] = (f2, f1, f0)

# We have F_1(x_g) = 0 (mod p) and F_2(x_g) = 0 (mod p).
# F_i(x_g) = f2*x_g^2 + f1*x_g + f0 = 0 (mod p)
# We can eliminate the x_g^2 term to get a linear equation in x_g.
f2_1, f1_1, f0_1 = [c % p for c in F_coeffs[1]]
f2_2, f1_2, f0_2 = [c % p for c in F_coeffs[2]]

# (f2_2 * F_1 - f2_1 * F_2)(x_g) = 0 (mod p)
# This gives: (f2_2*f1_1 - f2_1*f1_2)*x_g + (f2_2*f0_1 - f2_1*f0_2) = 0 (mod p)
L1 = (f2_2 * f1_1 - f2_1 * f1_2) % p
L0 = (f2_2 * f0_1 - f2_1 * f0_2) % p

# Solve L1*x_g + L0 = 0 (mod p) for x_g
xg = (-L0 * pow(L1, -1, p)) % p
print(f"Found generator x-coordinate x_g = {xg}")

# Find 'a' using D_1(x_g) / (x_1 - x_2) = 2a (mod p)
d2_1, d1_1, d0_1 = [c % p for c in d_coeffs[1]]
d1_at_xg = (d2_1 * xg**2 + d1_1 * xg + d0_1) % p
a_times_2 = (d1_at_xg * pow(x[1] - x[2], -1, p)) % p
a = (a_times_2 * pow(2, -1, p)) % p
print(f"Found curve parameter a = {a}")

# Find 'b' using C_1(x_g) = 2*x_g^3 + 2a(x_1+x_g) + 4b (mod p)
K3_1, K2_1, K1_1, K0_1 = [c % p for c in C_coeffs[1]]
C1_at_xg = (K3_1 * xg**3 + K2_1 * xg**2 + K1_1 * xg + K0_1) % p
b_times_4 = (C1_at_xg - 2 * pow(xg, 3, p) - a_times_2 * (x[1] + xg)) % p
b = (b_times_4 * pow(4, -1, p)) % p
print(f"Found curve parameter b = {b}")

# --- Step 3: Construct the flag ---
flag_val = p + a + b
flag_hex = hex(flag_val).lstrip('0x')

print("\n" + "="*50)
print(f"SUCCESS! Recovered curve parameters.")
print(f"  p = {p}")
print(f"  a = {a}")
print(f"  b = {b}")
print(f"\n  FLAG hint: hex(a+b+p) = {hex(flag_val)}")
print(f"  Predicted Flag: hacktoday{{{flag_hex}}}")
print("="*50)
