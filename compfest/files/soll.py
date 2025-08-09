import math
from Crypto.Util.number import inverse, long_to_bytes, GCD

# Provided values from the encryption script
n = 105375332609681406515521070043624487782870196469191202161434435531817940797270096886963495613362630149726295573449318680766414229677517682441830990791937099476820215035329281663818952921640911864146786915767893480415096397401467294479247404193884100343032732555022965900945086176438781154250207246166555647819
o1 = 77633598805092640252724107910395222743707418498331661189888724505381859694624522363159360564093918240382178585305319104811978787648604211175237899879841354634012079538469832859655067901694047617975823882351549659190376576638974977699045922795589181771284109834805293637783792031515473496804956462795626934818
o2 = 47429151844475742641042649495407207662566851803789329455756849511508428188444666235575337458509278378043440668303749169805120807459770548206797504115709846618485098694340179746812314900747328860355887054449308844370972363371972119596004863894202184305426870041561045629249134118889938654187837181030481512607
e1 = 186867715974359025539631582285150663971
e2 = 337065940616672019740199340023447546329
ct = 16127635971745761249117457383238357500818225865528781227818178295767094522191015256304698417447261196635354815589533608289075225290218976735930144917429170204631913040282911740200678626608196556229117931217102495952857640280769261620708029036539274328113707476723320511409928978108912915377499577509818504791

def solve():
    """
    This function decrypts the message by factoring n and then performing standard RSA decryption.
    The main steps are:
    1. Define the relationship between the hidden values x and y.
    2. Use polynomial algebra to find the ratio Z = x/y mod n.
    3. Use Z to factor n into p and q.
    4. With p and q known, calculate the RSA private key and decrypt the ciphertext.
    """
    print("Starting decryption process...")

    # Step 1: Define the relationship between x and y.
    # The encryption uses x = p + 5*q and y = 2*p - 3*q.
    # Through linear algebra, we find that (2x - y) = 13q and (3x + 5y) = 13p.
    # This implies (2x - y)(3x + 5y) = 169pq = 169n, which is 0 mod n.
    # Expanding this gives 6x^2 + 7xy - 5y^2 = 0 (mod n).
    # Dividing by y^2 (which is safe as y is coprime to n), we get a quadratic equation for Z = x/y:
    # 6Z^2 + 7Z - 5 = 0 (mod n).
    # Let's call this polynomial P(Z).

    # Step 2: Find Z = x/y.
    # We have o1 = x^e1 (mod n) and o2 = y^e2 (mod n).
    # Let E = e1 * e2. We can compute Z^E mod n.
    # Z^E = (x/y)^E = x^E / y^E = (x^e1)^e2 / (y^e2)^e1 = o1^e2 / o2^e1 (mod n).
    E = e1 * e2
    print(f"Calculated combined exponent E = e1*e2")

    o1_pow_e2 = pow(o1, e2, n)
    o2_pow_e1 = pow(o2, e1, n)
    inv_o2_pow_e1 = inverse(o2_pow_e1, n)
    
    # C is the value of Z^E mod n
    C = (o1_pow_e2 * inv_o2_pow_e1) % n
    print(f"Calculated C = Z^E mod n")

    # We now have two polynomials that have Z as a root modulo n:
    # P1(T) = 6T^2 + 7T - 5
    # P2(T) = T^E - C
    # We can find Z by finding a linear polynomial aT + b that is a combination of P1 and P2.
    # This is done by computing T^E mod P1(T).
    
    # We need to compute T^E in the ring R = Z_n[T] / (6T^2 + 7T - 5).
    # In this ring, 6T^2 = -7T + 5, so T^2 = (-7T + 5) * 6^-1.
    inv6 = inverse(6, n)
    # Coefficients for T^2 = c1*T + c0
    c1 = (-7 * inv6) % n
    c0 = (5 * inv6) % n

    def poly_mul(poly1, poly2):
        """Multiplies two polynomials of degree 1 in our ring."""
        # poly is [b, a] for aT + b
        b1, a1 = poly1
        b2, a2 = poly2
        # (a1*T + b1)(a2*T + b2) = a1a2*T^2 + (a1b2 + b1a2)T + b1b2
        # Substitute T^2 = c1*T + c0
        # = a1a2(c1*T + c0) + (a1b2 + b1a2)T + b1b2
        # = (a1a2*c1 + a1b2 + b1a2)T + (a1a2*c0 + b1b2)
        a_new = (a1 * a2 * c1 + a1 * b2 + b1 * a2) % n
        b_new = (a1 * a2 * c0 + b1 * b2) % n
        return [b_new, a_new]

    def poly_pow(exp):
        """Computes T^exp in our ring using exponentiation by squaring."""
        res = [1, 0]  # Represents 1
        base = [0, 1] # Represents T
        while exp > 0:
            if exp % 2 == 1:
                res = poly_mul(res, base)
            base = poly_mul(base, base)
            exp //= 2
        return res

    print("Computing T^E mod (6T^2 + 7T - 5) via polynomial exponentiation...")
    # T^E mod P1(T) results in a linear polynomial aT + b
    b, a = poly_pow(E)
    print("Polynomial exponentiation complete.")

    # Now we know a*Z + b = C (mod n). We can solve for Z.
    # a*Z = C - b => Z = (C - b) * a^-1
    inv_a = inverse(a, n)
    Z = ((C - b) * inv_a) % n
    print(f"Successfully recovered Z = x/y mod n")

    # Step 3: Factor n using Z.
    # The roots of 6T^2 + 7T - 5 = (2T - 1)(3T + 5) = 0 are T=1/2 and T=-5/3.
    # We know Z = x/y is congruent to one root mod p and the other mod q.
    # Specifically, Z = -5/3 (mod p) and Z = 1/2 (mod q).
    # This means (Z - (-5/3)) is a multiple of p.
    # So, gcd(Z + 5/3, n) will give us p.
    inv2 = inverse(2, n)
    inv3 = inverse(3, n)
    
    r1 = (1 * inv2) % n
    r2 = (-5 * inv3) % n

    p = GCD(Z - r2, n)
    q = n // p

    # Verification
    if p * q == n:
        print(f"\nSuccessfully factored n!")
        print(f"p = {p}")
        print(f"q = {q}")
    else:
        print("Factoring failed. Trying the other root.")
        p = GCD(Z - r1, n)
        q = n // p
        if p * q == n:
            print(f"\nSuccessfully factored n!")
            print(f"p = {p}")
            print(f"q = {q}")
        else:
            print("Factoring failed completely. Exiting.")
            return

    # Step 4: Decrypt the flag.
    # Now that we have p and q, we can perform standard RSA decryption.
    phi = (p - 1) * (q - 1)
    e_main = 65537
    d_main = inverse(e_main, phi)

    # Decrypt the ciphertext
    m_combined = pow(ct, d_main, n)

    # The original message was m * o1 * o2. We need to divide by o1 and o2.
    inv_o1_o2 = inverse((o1 * o2) % n, n)
    m = (m_combined * inv_o1_o2) % n

    # Convert the message from a long integer back to bytes.
    flag = long_to_bytes(m)
    print("\nDecryption successful!")
    print(f"Flag: {flag.decode()}")


if __name__ == '__main__':
    solve()
