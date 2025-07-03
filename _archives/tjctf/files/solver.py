from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot
from functools import reduce

def chinese_remainder_theorem(n, a):
    sum_val = 0
    prod = reduce(lambda a, b: a * b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum_val += a_i * inverse(p, n_i) * p
    return sum_val % prod

def inverse(a, n):
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr
    if r > 1:
        raise Exception("a is not invertible")
    if t < 0:
        t = t + n
    return t

e = 229

ns = []
cs = []

# Parse the output.txt file
with open('files/output.txt', 'r') as f:
    lines = f.readlines()
    for line in lines:
        line = line.strip()
        if line.startswith('e = '):
            e = int(line.split(' = ')[1])
        elif line.startswith('n'):
            ns.append(int(line.split(' = ')[1]))
        elif line.startswith('c'):
            cs.append(int(line.split(' = ')[1]))

# Ensure we have enough (n, c) pairs for Hastad's Broadcast Attack
if len(ns) < e:
    print(f"Error: Not enough (n, c) pairs. Expected at least {e}, got {len(ns)}")
    exit()

# Use only the first 'e' pairs for CRT
ns_crt = ns[:e]
cs_crt = cs[:e]

# Apply Chinese Remainder Theorem
m_e_crt = chinese_remainder_theorem(ns_crt, cs_crt)

# Calculate the e-th root
# gmpy2.iroot returns (root, exact_p)
# We need to ensure that m_e_crt is indeed m^e, so the root should be exact.
m_long, is_exact = iroot(m_e_crt, e)

if is_exact:
    flag = long_to_bytes(m_long)
    print(f"Recovered Flag: {flag.decode('utf-8', errors='ignore')}")
else:
    print("Failed to recover the flag: e-th root was not exact.")
