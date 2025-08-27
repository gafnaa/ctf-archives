import sys
from Crypto.Util.number import long_to_bytes, bytes_to_long
from mtsp import MersenneTwisterPredictor

# --- Helper Functions ---

def parse_output(filename):
    """
    Parses the output file from chall.py to extract all necessary values.
    """
    with open(filename, 'r') as f:
        lines = f.readlines()

    bits = []
    # The first 19968 lines are the 'even'/'odd' bits
    for i in range(19968):
        if "even" in lines[i]:
            bits.append(0)
        elif "odd" in lines[i]:
            bits.append(1)

    # The rest of the lines contain the crypto parameters
    data = {}
    for line in lines[19968:]:
        if '=' in line:
            key, value = line.split('=', 1)
            key = key.strip()
            # Use exec to handle lists and large integers
            # Be cautious with exec on untrusted input
            try:
                data[key] = eval(value.strip())
            except:
                print(f"Warning: Could not parse line: {line.strip()}")

    return bits, data

def predict_noise(bits):
    """
    Reconstructs the Mersenne Twister state from the leaked LSBs
    and predicts the four 1024-bit random noise values.
    """
    print("[+] Reconstructing PRNG state from leaked bits...")
    
    # Initialize the predictor
    predictor = MersenneTwisterPredictor()
    
    # Feed the 19968 leaked LSBs to the predictor
    for i in range(624):
        # We need to provide 32-bit numbers, but we only have the LSB.
        # The library is smart enough to solve for the full state.
        # We pass the bit as an integer (0 or 1).
        predictor.setrandbits(bits[i*32], 1)

    print("[+] PRNG state successfully recovered.")
    print("[+] Predicting the random noise values...")

    # Helper to generate a 1024-bit number, mimicking Python's `getrandbits`
    def get_1024_bits(pred):
        # 1024 = 32 * 32, so we combine 32 outputs of 32 bits each
        val = 0
        for _ in range(32):
            # The predictor's getrandbits returns a full 32-bit integer
            rand_32bit = pred.getrandbits(32)
            val = (val << 32) | rand_32bit
        return val

    # Predict the four noise values in the same order as the challenge script
    r1 = get_1024_bits(predictor) # For c1_test
    r2 = get_1024_bits(predictor) # For c2_test
    r3 = get_1024_bits(predictor) # For c1_secret
    r4 = get_1024_bits(predictor) # For c2_secret
    
    # The challenge script prints in order: c1_test, c2_test, c1_secret, c2_secret
    # So the noises correspond to these in order.
    # Let's return them in a dictionary for clarity.
    return {'c1_test': r1, 'c2_test': r2, 'c1_secret': r3, 'c2_secret': r4}


def solve_poly_hensel(coeffs, poly_result, p, k, n):
    """
    Solves the polynomial P(m) - poly_result = 0 mod n using Hensel's Lemma.
    """
    print("[+] Solving polynomial equation using Hensel's Lemma.")
    
    # Define the polynomial function f(x) = P(x) - poly_result
    def f(x):
        res = -poly_result
        for i in range(len(coeffs)):
            res = (res + coeffs[i] * pow(x, i, n)) % n
        return res

    # Define the derivative of the polynomial, f'(x)
    def f_deriv(x):
        res = 0
        for i in range(1, len(coeffs)):
            res = (res + i * coeffs[i] * pow(x, i - 1, n)) % n
        return res

    # Step 1: Find roots modulo p
    print(f"[+] Searching for roots modulo p = {p}...")
    roots_mod_p = []
    for m in range(p):
        if f(m) % p == 0:
            roots_mod_p.append(m)
            print(f"  - Found root mod p: {m}")

    if not roots_mod_p:
        print("[-] No roots found modulo p. Cannot proceed.")
        return None

    # Step 2: Lift each root using Hensel's Lemma
    for m0 in roots_mod_p:
        print(f"\n[+] Lifting root {m0} from mod p to mod n...")
        
        # Check if the derivative is zero, which is a condition for simple lifting
        deriv_val = f_deriv(m0) % p
        if deriv_val == 0:
            print(f"  - Derivative is 0 mod p for root {m0}. Hensel's simple lifting fails.")
            continue
        
        # Calculate the modular inverse of the derivative
        deriv_inv = pow(deriv_val, -1, p)
        
        m_current = m0
        p_power = p
        
        for _ in range(1, k):
            # Calculate the next iteration for the root
            f_val = f(m_current)
            
            # The lifting formula: m_{j+1} = m_j - f(m_j) * (f'(m0))^-1
            # We need to compute t = (f(m_current) / p_power) mod p
            t = ( (f_val // p_power) * (-deriv_inv) ) % p
            
            m_current = m_current + t * p_power
            p_power *= p

        print(f"  - Lifted root to mod n: {m_current}")
        
        # Convert the final root to bytes to see if it's the flag
        try:
            flag = long_to_bytes(m_current)
            if b'flag' in flag or b'FLAG' in flag or b'{' in flag.decode():
                print(f"\n[SUCCESS] Found potential flag: {flag.decode()}")
                return flag
        except Exception as e:
            print(f"  - Could not convert root to bytes: {e}")
            
    return None

# --- Main Decryption Logic ---

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <output_file>")
        sys.exit(1)
        
    output_file = sys.argv[1]
    
    # 1. Parse all data from the challenge output
    print(f"[+] Parsing data from {output_file}...")
    bits, data = parse_output(output_file)
    p, n, coeffs = data['p'], data['n'], data['coeffs']
    C_noisy = {
        'c1_test': data['c1_test'],
        'c2_test': data['c2_test'],
        'c1_secret': data['c1_secret'],
        'c2_secret': data['c2_secret']
    }
    k = 100 # from chall.py
    
    # 2. Predict the noise values by cracking the PRNG
    noise = predict_noise(bits)
    
    # 3. Remove the noise to get the true ciphertext values
    print("[+] Removing noise from ciphertext values...")
    c1_test = C_noisy['c1_test'] - noise['c1_test']
    c2_test = C_noisy['c2_test'] - noise['c2_test']
    c1_secret = C_noisy['c1_secret'] - noise['c1_secret']
    c2_secret = C_noisy['c2_secret'] - noise['c2_secret']
    
    # Sanity check: c1_test and c1_secret should be identical
    if c1_test == c1_secret:
        print("[+] Sanity check passed: c1_test == c1_secret.")
    else:
        print("[-] Sanity check failed. PRNG prediction might be incorrect.")
        sys.exit(1)
        
    # 4. Recover the encrypted polynomial result
    print("[+] Recovering the polynomial result...")
    test_msg = bytes_to_long(b"This is just a test message.")
    
    # The relationship is: poly_result = (test_msg * c2_secret * c2_test^-1) % n
    inv_c2_test = pow(c2_test, -1, n)
    poly_result = (c2_secret * test_msg * inv_c2_test) % n
    print(f"  - Recovered poly_result (first 20 digits): {str(poly_result)[:20]}...")
    
    # 5. Solve the polynomial equation for the message `m`
    solve_poly_hensel(coeffs, poly_result, p, k, n)


if __name__ == "__main__":
    main()
