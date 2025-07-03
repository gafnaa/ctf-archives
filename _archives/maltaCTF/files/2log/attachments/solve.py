import math
from decimal import Decimal, getcontext

# Set precision for Decimal calculations
getcontext().prec = 200

def solve_k1():
    """
    Solves for k1 based on h2 and h3 using the corrected matrix exponentiation formula.
    """
    p = 2**255 - 19
    h2 = 6525529513224929513242286153522039835677193513612437958976590021494532059727
    h3 = 42423271339336624024407863370989392004524790041279794366407913985192411875865
    l = 1337

    inv_l = pow(l, -1, p)
    inv_2 = pow(2, -1, p)

    # From h2 = l**k1 + 32*h3
    l_pow_k1 = (h2 - 32 * h3) % p
    l_pow_k1_minus_1 = (l_pow_k1 * inv_l) % p
    
    k1 = (h3 * inv_2 * pow(l_pow_k1_minus_1, -1, p)) % p
    return k1

def find_k0_and_reconstruct_flag(k1, h1):
    """
    Iterates through possible flag lengths, finds k0, and reconstructs the flag.
    """
    prefix_bytes = b'maltactf{'
    prefix_int = int.from_bytes(prefix_bytes, 'big')

    # Loop over possible even flag lengths
    for L in range(42, 61, 2):
        len_k0b = L // 2 + 4
        len_k1b = L // 2

        if k1.bit_length() > len_k1b * 8:
            continue

        len_k1_suffix = len_k1b - 4
        m = k1 >> (len_k1_suffix * 8)

        # Get a precise estimate for k0
        h1_dec = Decimal(h1)
        log2_1337 = Decimal(1337).log10() / Decimal(2).log10()
        k0_est = h1_dec / log2_1337
        try:
            for _ in range(5):
                log2_k0_term = (Decimal(64) * k0_est).log10() / Decimal(2).log10()
                k0_est = (h1_dec - log2_k0_term) / log2_1337 + Decimal(1)
        except Exception:
            continue

        k0_center = int(k0_est)

        # Search in a small range around the estimate
        for i in range(-2000, 2000):
            k_cand = k0_center + i

            if not ((len_k0b - 1) * 8 < k_cand.bit_length() <= len_k0b * 8):
                continue
            
            # Constraint 1: Check prefix
            if (k_cand >> ((len_k0b - len(prefix_bytes)) * 8)) != prefix_int:
                continue
            
            # Constraint 2: Check overlapping bytes
            if (k_cand % (256**4)) != m:
                continue

            # Found it! Reconstruct the flag.
            k0_bytes = k_cand.to_bytes(len_k0b, 'big')
            k1_bytes = k1.to_bytes(len_k1b, 'big')
            flag_bytes = k0_bytes[:-4] + k1_bytes
            return flag_bytes.decode()
            
    return None

def main():
    h1 = 1825310437373651425737133387514704339138752170433274546111276309

    k1 = solve_k1()
    flag = find_k0_and_reconstruct_flag(k1, h1)

    if flag:
        print(f"Flag found: {flag}")
    else:
        print("Failed to find the flag.")

if __name__ == '__main__':
    main()