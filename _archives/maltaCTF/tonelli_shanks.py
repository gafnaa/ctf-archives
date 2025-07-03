# Implementation of Tonelli-Shanks algorithm for modular square root
# Based on https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm

def legendre_symbol(a, p):
    """Compute the Legendre symbol (a/p)"""
    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

def tonelli_shanks(n, p):
    """
    Compute sqrt(n) mod p using Tonelli-Shanks algorithm.
    Returns one of the square roots, or None if no square root exists.
    """
    if legendre_symbol(n, p) != 1:
        return None

    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)

    s = 0
    q = p - 1
    while q % 2 == 0:
        q //= 2
        s += 1

    if s == 1:
        return pow(n, (p + 1) // 4, p)

    z = 2
    while legendre_symbol(z, p) != -1:
        z += 1

    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)

    while True:
        if t == 0:
            return 0
        if t == 1:
            return r
        
        i = 0
        temp_t = t
        while temp_t != 1 and i < m:
            temp_t = (temp_t * temp_t) % p
            i += 1
        
        if i == m:
            return None # Should not happen if n is a quadratic residue

        b = pow(c, pow(2, m - i - 1), p)
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p
