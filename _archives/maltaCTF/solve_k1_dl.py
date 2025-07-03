import math

# Given values from solve_k1_part1.py output
p = 57896044618658097711785492504343953926634992332820282019728792003956564819949
lambda1 = 1342
lambda2 = 1332
X_target = 57700028922601719308383898057073939051483214784314849593840947547341090170562
Y_target = 19271806081892892321701058715158840808764241576376723820987753633248725251084

print("Attempting to find k1 as a power of 2...")

# Check if k1 is a power of 2
current_power_lambda1 = lambda1
current_power_lambda2 = lambda2

found_k1 = None

# Max bits for k1 is 176 (from 22 bytes)
for x in range(1, 177): # k1 = 2^x
    if current_power_lambda1 == X_target and current_power_lambda2 == Y_target:
        found_k1 = 2**x
        break
    
    # Compute next power of 2
    current_power_lambda1 = (current_power_lambda1 * current_power_lambda1) % p
    current_power_lambda2 = (current_power_lambda2 * current_power_lambda2) % p

    if x % 10 == 0:
        print(f"Checked 2^{x}...")

if found_k1:
    print(f"Found k1 = {found_k1}")
else:
    print("k1 is not a power of 2 in the range checked.")

# If k1 is not a power of 2, then it's a general discrete log.
# Let's try to use a generic discrete log solver if available, or implement a small BSGS for testing.
# Given the size of p, a full BSGS is not feasible.

# What if k1 is small?
# The problem states k1 is from 22 bytes, so it's large.

# Let's consider the possibility that the problem is a "Pollard's Rho" or "Baby-Step Giant-Step"
# but with a very small search space due to some property.
# Or maybe the order of the elements is small.

# Let's try to find the order of lambda1 and lambda2.
# This requires factoring p-1.
# p-1 = 2**255 - 20 = 4 * (2**253 - 5)
# Let q_prime = 2**253 - 5.
# If q_prime is prime, then the order of elements can be 1, 2, 4, q_prime, 2*q_prime, 4*q_prime.
# If the order is small, then discrete log is easy.

# Let's check if q_prime is prime. This is a very large number.
# I will use a primality test from a library if available.
# `gmpy2.is_prime` can test primality.

import gmpy2

q_prime = (2**253 - 5)
print(f"Checking primality of q_prime = {q_prime}")
is_q_prime_prime = gmpy2.is_prime(q_prime)
print(f"Is q_prime prime? {is_q_prime_prime}")

# If q_prime is prime, then the order of lambda1 and lambda2 will be either 1, 2, 4, q_prime, 2*q_prime, or 4*q_prime.
# If the order is q_prime or 2*q_prime or 4*q_prime, then discrete log is still hard.

# What if the problem is a "small exponent" discrete log?
# This is usually solved by brute force or Pollard's Rho for small exponents.
# But k1 is 176 bits.

# Let's re-read the problem statement carefully. "2log/attachments/chall.sage"
# The "2log" part might be a hint.
# Could it be that k1 is small in base 2? i.e., k1 has few set bits?
# Or k1 is a power of 2, which I'm checking.

# If k1 is not a power of 2, then I need a general discrete log solver.
# I will try to use the `Crypto.Util.number.long_to_bytes` and `bytes_to_long` for flag reconstruction.
# But first, I need k1.

# Let's consider the possibility that the problem is a "Pollard's Rho" or "Baby-Step Giant-Step"
# but with a very small search space due to some property.
# Or maybe the order of the elements is small.

# If the order of lambda1 is small, then we can iterate through powers.
# Let's try to find the order of lambda1.
# This is usually done by factoring p-1 and checking powers for each factor.

# Given the CTF context, and the fact that Sage's discrete_log is used,
# there might be a specific property of the field or the base that makes it easy.
# For example, if the field is a prime field GF(p), and p-1 has only small prime factors,
# then Pohlig-Hellman algorithm can be used.
# But we determined p-1 has a large prime factor q_prime.

# What if the problem is a "small exponent" discrete log?
# This is usually solved by brute force or Pollard's Rho for small exponents.
# But k1 is 176 bits.

# Let's try to use the `Crypto.Util.number.long_to_bytes` and `bytes_to_long` for flag reconstruction.
# But first, I need k1.

# I will try to implement a simple BSGS for a small range to see if it works.
# But k1 is 176 bits, so BSGS is not feasible.

# The only remaining possibility for a direct discrete log is if the order of lambda1 is small.
# Let's check the order of lambda1 and lambda2.
# Order of g mod p is the smallest k such that g^k = 1 mod p.
# This requires factoring p-1.

# Let's assume for a moment that the problem is solvable with a standard discrete log.
# I will try to find a Python library that implements discrete log for large numbers.
# `pycryptodome` does not have a direct discrete log function.
# `gmpy2` does not have a direct discrete log function.

# I will try to implement a very basic discrete log solver for testing purposes,
# but it will only work for very small exponents.
# This is unlikely to be the solution for k1.

# Let's re-evaluate the "2log" hint.
# Could it be that k1 is related to the bit length of something?
# h1 = ((G**k0)[0][0]).bit_length() - randint(-2**32, 2**32)
# This is for k0.

# What if the problem is a "collision" problem?
# Like finding x such that g^x = h.
# If we have two equations:
# lambda1^k1 = X_target (mod p)
# lambda2^k1 = Y_target (mod p)
# We can take the ratio: (lambda1/lambda2)^k1 = X_target/Y_target (mod p)
# Let base = (lambda1 * mod_inverse(lambda2, p)) % p
# Let target = (X_target * mod_inverse(Y_target, p)) % p
# Then base^k1 = target (mod p).
# This reduces it to a single discrete log problem, but doesn't make it easier if the order is large.

# Let's try to compute the order of `base = (lambda1 * mod_inverse(lambda2, p)) % p`.
# This still requires factoring `p-1`.

# I will proceed with the assumption that `k1` is a power of 2, as hinted by "2log" and the feasibility of checking it.
# If not, I will need to reconsider the approach.
