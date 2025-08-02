def tonelli_shanks(n, p):
    """
    Tonelli-Shanks algorithm to find a modular square root of n modulo p.
    p must be an odd prime.
    Returns a number x such that x^2 = n (mod p), or None if no such root exists.
    """
    if pow(n, (p - 1) // 2, p) != 1:
        # n is not a quadratic residue, so no square root exists.
        return None

    # Factor p-1 as Q * 2^S
    Q = p - 1
    S = 0
    while Q % 2 == 0:
        Q //= 2
        S += 1

    # If S=1, we are in the simpler p % 4 == 3 case
    if S == 1:
        return pow(n, (p + 1) // 4, p)

    # Find a non-quadratic residue 'z'
    z = 2
    while pow(z, (p - 1) // 2, p) == 1:
        z += 1

    M = S
    c = pow(z, Q, p)
    t = pow(n, Q, p)
    R = pow(n, (Q + 1) // 2, p)

    while True:
        if t == 0:
            return 0
        if t == 1:
            return R
        
        # Use a loop to find the smallest i > 0 such that t^(2^i) = 1
        i = 0
        temp = t
        while temp != 1:
            temp = (temp * temp) % p
            i += 1
            if i == M:
                return None

        b = pow(c, pow(2, M - i - 1, p - 1), p)
        M = i
        c = (b * b) % p
        t = (t * c) % p
        R = (R * b) % p

def solve():
    """
    Solves the elliptic curve discrete logarithm problem by exploiting a singular curve vulnerability.
    The curve is cuspidal, so the group is additive. We solve the linear congruence in F_p.
    This version uses the correct Tonelli-Shanks algorithm and tests both possible singular points.
    """
    # Provided parameters from the challenge
    p = 3059506932006842768669313045979965122802573567548630439761719809964279577239571933
    a = 2448848303492708630919982332575904911263442803797664768836842024937962142592572096
    Gx = 3
    Qx = 1461547606525901279892022258912247705593987307619875233742411837094451720970084133

    # --- Step 1: Find the two possible singular points (xs, 0) ---
    # A singular point (xs, 0) satisfies 3*xs^2 + a = 0.
    inv3 = pow(3, -1, p)
    xs_squared = (-a * inv3) % p

    # Use Tonelli-Shanks for the modular square root.
    xs_root = tonelli_shanks(xs_squared, p)
    if xs_root is None:
        print("[!] Failed to find singular point. -a/3 is not a quadratic residue.")
        return
    
    # There are two possible values for xs, let's test both.
    possible_xs = [xs_root, p - xs_root]

    for xs in possible_xs:
        print("\n" + "="*50)
        print(f"[*] Testing singular point x-coordinate: xs = {xs}")

        # --- Step 2: Find y-coords for G and Q ---
        # We need b to find y. For a singular curve, b = 2*xs^3 mod p.
        b = (2 * pow(xs, 3, p)) % p
        Gy_squared = (pow(Gx, 3, p) + a * Gx + b) % p
        Qy_squared = (pow(Qx, 3, p) + a * Qx + b) % p

        Gy = tonelli_shanks(Gy_squared, p)
        Qy = tonelli_shanks(Qy_squared, p)

        if Gy is None or Qy is None:
            print("[!] Could not find y-coordinates for this xs, skipping.")
            continue
        
        # Verification check
        if pow(Gy, 2, p) != Gy_squared:
            print("[!] Sanity check failed: Gy^2 != Gy_squared. Tonelli-Shanks might have an issue.")
            continue

        print(f"[*] Found full points G and Q (using one of two possible y-coords):")
        print(f"    G = ({Gx}, {Gy})")
        print(f"    Q = ({Qx}, {Qy})")

        # --- Step 3: Map EC points to the additive group F_p ---
        print("[*] Assuming CUSPIDAL curve with ADDITIVE group law.")
        print("[*] Using isomorphism phi(x,y) = (x - xs) / y.")

        try:
            # Map G to g in (F_p, +)
            g = ((Gx - xs) * pow(Gy, -1, p)) % p
            # Map Q to h in (F_p, +)
            h = ((Qx - xs) * pow(Qy, -1, p)) % p

            print(f"    Mapped G -> g = {g}")
            print(f"    Mapped Q -> h = {h}")

            # --- Step 4: Solve the Linear Congruence in F_p ---
            # Q = flag * G  =>  h = flag * g (mod p)
            # flag = h * g^(-1) (mod p)
            inv_g = pow(g, -1, p)

            # Candidate 1: Uses (+Gy, +Qy) or (-Gy, -Qy)
            flag1 = (h * inv_g) % p
            bytes1 = flag1.to_bytes((flag1.bit_length() + 7) // 8, 'big')
            print(f"\n[*] Trying flag candidate 1: {flag1}")
            print(f"    Bytes: {bytes1}")
            if bytes1.startswith(b"wwf{"):
                print("\n" + "="*50)
                print(f"  SUCCESS! Found the correct flag: {bytes1.decode()}")
                print("="*50)
                return

            # Candidate 2: Uses (+Gy, -Qy) or (-Gy, +Qy)
            # This is equivalent to h -> -h
            flag2 = (-h * inv_g) % p
            bytes2 = flag2.to_bytes((flag2.bit_length() + 7) // 8, 'big')
            print(f"\n[*] Trying flag candidate 2: {flag2}")
            print(f"    Bytes: {bytes2}")
            if bytes2.startswith(b"wwf{"):
                print("\n" + "="*50)
                print(f"  SUCCESS! Found the correct flag: {bytes2.decode()}")
                print("="*50)
                return

        except Exception as e:
            print(f"[!] Failed to solve for flag for this xs: {e}")

    print("\n[!] All attempts failed to find the correct flag.")


if __name__ == '__main__':
    solve()
