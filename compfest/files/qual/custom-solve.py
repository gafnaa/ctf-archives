# Import necessary libraries
from pwn import *
from Crypto.Util.number import long_to_bytes
import gmpy2

# --- Continued Fractions Helper ---
def continued_fraction(n, d):
    """Calculates the continued fraction of n/d."""
    res = []
    while d:
        q, r = divmod(n, d)
        res.append(q)
        n, d = d, r
    return res

def convergents(cf):
    """Calculates the convergents from a continued fraction."""
    n0, n1 = cf[0], cf[0] * cf[1] + 1
    d0, d1 = 1, cf[1]
    yield (n0, d0)
    yield (n1, d1)
    for i in range(2, len(cf)):
        n2 = cf[i] * n1 + n0
        d2 = cf[i] * d1 + d0
        yield (n2, d2)
        n0, n1 = n1, n2
        d0, d1 = d1, d2

# --- Main Attack Logic ---
def solve():
    """
    Connects to the server, retrieves crypto parameters,
    and performs the attack to decrypt the flag.
    """
    # Connect to the remote server
    r = remote('ctf.compfest.id', 7102)

    # Receive N
    r.recvuntil(b'N:  ')
    N = int(r.recvline().strip())
    print(f"[*] Received N: {N}")

    # Send a large bound to proceed
    bound = 2**1024
    r.sendlineafter(b'Enter bound: ', str(bound).encode())
    print(f"[*] Sent bound: {bound}")

    # Receive e and ct
    r.recvuntil(b'e: ')
    e = int(r.recvline().strip())
    print(f"[*] Received e: {e}")

    r.recvuntil(b'ct: ')
    ct = int(r.recvline().strip())
    print(f"[*] Received ct: {ct}")

    r.close()

    # --- Wiener's Attack Variation ---
    # The relationship is e*d = 1 (mod phi), so e*d = k*phi + 1 for some integer k.
    # This means e/phi ≈ k/d.
    # In this problem, phi = (p^2-1)(q^2-1) which is very close to N^2.
    # So, we can approximate e/N^2 ≈ k/d.
    # We find k/d by computing the convergents of the continued fraction of e/N^2.

    print("\n[*] Starting attack...")
    # Calculate continued fraction of e / N^2
    # This is the corrected line
    cf = continued_fraction(e, N**2)
    
    # Calculate convergents
    convs = convergents(cf)

    for k, d in convs:
        if k == 0:
            continue

        # For each convergent k/d, we test if it's the correct private key.
        # The relationship is e*d - k*phi = 1, so phi = (e*d - 1) // k
        
        # Check if (e*d - 1) is divisible by k
        if (e * d - 1) % k != 0:
            continue

        phi = (e * d - 1) // k

        # Now we have a candidate for phi. We can find p and q.
        # phi = (p^2-1)(q^2-1) = p^2*q^2 - p^2 - q^2 + 1
        # phi = N^2 - (p^2 + q^2) + 1
        # p^2 + q^2 = N^2 - phi + 1
        # (p+q)^2 - 2pq = N^2 - phi + 1
        # (p+q)^2 - 2N = N^2 - phi + 1
        # (p+q)^2 = N^2 + 2N + 1 - phi = (N+1)^2 - phi
        # p+q = sqrt((N+1)^2 - phi)

        # Let's calculate (p+q)^2
        s_squared = (N + 1)**2 - phi
        
        # Check if s_squared is a perfect square
        is_sq, s_rem = gmpy2.isqrt_rem(s_squared)
        if s_rem == 0:
            s = is_sq # s is now p+q
            # We found p+q. Now solve for p and q using the quadratic equation:
            # x^2 - s*x + N = 0
            # The roots are (s +/- sqrt(s^2 - 4N)) / 2
            delta_sq = s**2 - 4 * N
            if delta_sq < 0:
                continue
            is_delta_sq, delta_rem = gmpy2.isqrt_rem(delta_sq)
            if delta_rem == 0:
                delta = is_delta_sq
                # Check if (s+delta) is even
                if (s + delta) % 2 == 0:
                    p = (s + delta) // 2
                    q = (s - delta) // 2
                    if p * q == N:
                        print(f"\n[+] Found factors p and q!")
                        print(f"p: {p}")
                        print(f"q: {q}")

                        # Decrypt the ciphertext
                        m = pow(ct, d, N)
                        flag = long_to_bytes(m)
                        print(f"\n[+] Flag: {flag.decode()}")
                        return

    print("\n[-] Attack failed. Could not find factors.")

if __name__ == "__main__":
    solve()
