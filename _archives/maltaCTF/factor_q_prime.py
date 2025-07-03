import gmpy2

q_prime = (2**253 - 5)
print(f"Attempting to factor q_prime = {q_prime}")

# gmpy2.factorize returns a list of (prime, exponent) tuples
# For very large numbers, this can still be slow or infeasible without special algorithms.
# However, since it's a CTF, there might be a small factor.
# Let's try trial division for small primes first.

def trial_division(n, limit):
    factors = []
    d = 2
    temp_n = n
    while d * d <= temp_n and d <= limit:
        if temp_n % d == 0:
            factors.append(d)
            while temp_n % d == 0:
                temp_n //= d
        d += 1
    if temp_n > 1:
        factors.append(temp_n)
    return factors

# Let's try trial division up to a reasonable limit, say 1000000.
# This is unlikely to find a factor of 2^253 - 5 unless it's very small.
# But it's worth a try.

# A more robust way is to use gmpy2's internal factoring.
# gmpy2.factorize is for mpz numbers.
# Let's convert q_prime to gmpy2.mpz
q_prime_mpz = gmpy2.mpz(q_prime)

# This might take a very long time or fail for such a large number.
# If it hangs, I'll need to reconsider.
# For CTF, sometimes factors are small or related to the problem.

# Let's try to use gmpy2.factorize directly.
# This function uses Pollard's rho and other methods.
# It might be slow.

# I will try to use a small trial division first, then if no small factors are found,
# I will try gmpy2.factorize.

print("Trying trial division for small factors...")
small_factors = trial_division(q_prime, 1000000)
print(f"Small factors found: {small_factors}")

if len(small_factors) > 1 and small_factors[-1] != q_prime:
    print("Found small factors, remaining number is composite or prime.")
    remaining_q = q_prime
    for f in small_factors[:-1]:
        remaining_q //= f
    print(f"Remaining q_prime after small factors: {remaining_q}")
    if gmpy2.is_prime(remaining_q):
        print("Remaining q_prime is prime.")
    else:
        print("Remaining q_prime is composite. Attempting gmpy2.factorize on remaining part.")
        # This part might be slow
        factors_remaining = gmpy2.factorize(gmpy2.mpz(remaining_q))
        print(f"Factors of remaining q_prime: {factors_remaining}")
else:
    print("No small factors found or q_prime is prime. Attempting gmpy2.factorize on full q_prime.")
    # This part might be very slow
    factors_full = gmpy2.factorize(q_prime_mpz)
    print(f"Factors of q_prime: {factors_full}")
