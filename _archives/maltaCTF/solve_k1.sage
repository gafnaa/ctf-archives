from sage.all import matrix, GF, ZZ, discrete_log

P = 2**255 - 19
F = GF(P)
G_orig = matrix(ZZ, [[1401, 2],[-2048, 1273]])
G_mod_P = matrix(F, G_orig)

print(f"G_mod_P: {G_mod_P}")

char_poly = G_mod_P.characteristic_polynomial()
print(f"Characteristic polynomial: {char_poly}")

eigenvalues = G_mod_P.eigenvalues()
print(f"Eigenvalues: {eigenvalues}")

# Verify product of eigenvalues
prod_eigenvalues = F(1)
for val in eigenvalues:
    prod_eigenvalues *= val
print(f"Product of eigenvalues: {prod_eigenvalues}")
print(f"Determinant of G_mod_P: {G_mod_P.det()}")

# Given h2 and h3
h2 = 6525529513224929513242286153522039835677193513612437958976590021494532059727
h3 = 42423271339336624024407863370989392004524790041279794366407913985192411875865

# Calculate c1 and c0
a = F(1401)
b = F(2)
c = F(-2048)
d = F(1273)

c1 = F(h3) * b^(-1)
c0 = F(h2) - c1 * a

print(f"c1: {c1}")
print(f"c0: {c0}")

# Calculate X and Y
# The eigenvalues list might not be in a fixed order, so let's assign them explicitly
lambda1 = F(1342)
lambda2 = F(1332)

X = c0 + c1 * lambda1
Y = c0 + c1 * lambda2

print(f"X (lambda1^k1): {X}")
print(f"Y (lambda2^k1): {Y}")

# Attempt discrete log for k1
# This part is expected to be hard if k1 is large
# k1 = discrete_log(X, lambda1)
# print(f"k1: {k1}")
