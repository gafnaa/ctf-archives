import gmpy2
from Crypto.Util.number import long_to_bytes

# Given values from the challenge
n = 144984891276196734965453594256209014778963203195049670355310962211566848427398797530783430323749867255090629853380209396636638745366963860490911853783867871911069083374020499249275237733775351499948258100804272648855792462742236340233585752087494417128391287812954224836118997290379527266500377253541233541409
c = 120266872496180344790010286239079096230140095285248849852750641721628852518691698502144313546787272303406150072162647947041382841125823152331376276591975923978272581846998438986804573581487790011219372437422499974314459242841101560412534631063203123729213333507900106440128936135803619578547409588712629485231
hint = 867001369103284883200353678854849752814597815663813166812753132472401652940053476516493313874282097709359168310718974981469532463276979975446490353988
e = 65537

def solve():
    """
    Solves the RSA challenge by recovering phi from the provided hint.
    """
    # Constants based on the problem description
    HINT_BITS = 500
    PRIME_BITS = 512
    
    # 2^500, used for reconstructing phi from the hint and the unknown upper bits
    mod = 1 << HINT_BITS
    
    # Since p and q are 512-bit primes, we know their approximate range:
    # 2^(511) < p, q < 2^512
    # This gives us a range for their sum s = p + q:
    # 2^512 < s < 2^513
    s_min = 1 << PRIME_BITS
    s_max = 1 << (PRIME_BITS + 1)

    # We know phi = n - (p+q) + 1, which means s = n - phi + 1.
    # We also know phi = k * (2^500) + hint, where k is the unknown upper part of phi.
    # By substituting phi, we get: s = n - (k * mod + hint) + 1
    # Let A = n - hint + 1. Then s = A - k * mod.
    A = n - hint + 1
    
    # We can use the bounds of s to find the bounds for k:
    # s_min < A - k * mod < s_max
    # After rearranging for k:
    # (A - s_max) / mod < k < (A - s_min) / mod
    k_lower_bound = (A - s_max) // mod
    k_upper_bound = (A - s_min) // mod

    print("Searching for k...")
    # Iterate through the small range of possible k values.
    for k in range(k_lower_bound, k_upper_bound + 2):
        # Reconstruct a candidate for phi
        phi_candidate = k * mod + hint
        
        # Calculate the corresponding s = p + q
        s_candidate = n - phi_candidate + 1
        
        # p and q are the roots of the quadratic equation: x^2 - s*x + n = 0
        # The discriminant is Delta = s^2 - 4n. It must be a perfect square.
        discriminant = s_candidate**2 - 4 * n
        
        if discriminant > 0:
            # gmpy2.isqrt_rem returns (sqrt, remainder).
            # If remainder is 0, it's a perfect square.
            root, remainder = gmpy2.isqrt_rem(discriminant)
            if remainder == 0:
                # We found a valid discriminant. Calculate p and q.
                p = (s_candidate - root) // 2
                q = (s_candidate + root) // 2
                
                # Final check: does p * q equal n?
                if p * q == n:
                    print("Factors found!")
                    print(f"p = {p}")
                    print(f"q = {q}")
                    
                    # We have the correct factors, so now we can decrypt.
                    phi = (p - 1) * (q - 1)
                    d = gmpy2.invert(e, phi)
                    m = pow(c, d, n)
                    flag = long_to_bytes(m)
                    
                    print("\n🎉 Decryption successful!")
                    print(f"Flag: {flag.decode()}")
                    return
    
    print("❌ Failed to find factors. The search range for k might be off.")

solve()