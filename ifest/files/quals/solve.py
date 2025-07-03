from pwn import *
from Crypto.Util.number import *
from sympy import nextprime
from sympy.ntheory.modular import crt  # Alternative CRT implementation

context.log_level = 'debug'

def main():
    # Connect to server
    r = remote("103.163.139.198", 8042)
    
    # Get leaked data
    r.recvuntil(b"N: ")
    N = int(r.recvline().strip(), 16)
    r.recvuntil(b"c1: ")
    c1 = int(r.recvline().strip(), 16)
    r.recvuntil(b"c2: ")
    c2 = int(r.recvline().strip(), 16)
    
    print(f"N = {N}")
    print(f"c1 = {c1}")
    print(f"c2 = {c2}")
    
    # Function to query the oracle
    def oracle(c1, c2):
        r.sendlineafter(b"> ", b"2")
        r.sendlineafter(b"c1 > ", hex(c1)[2:].encode())
        r.sendlineafter(b"c2 > ", hex(c2)[2:].encode())
        r.recvuntil(b"pt: ")
        pt = int(r.recvline().strip(), 16)
        return pt
    
    # Recover pw mod small primes using CRT
    primes = []
    mods = []
    
    # Start with 5 (from the leak)
    pw_mod_5 = oracle(c1, c2)
    primes.append(5)
    mods.append(pw_mod_5)
    print(f"pw mod 5 = {pw_mod_5}")
    
    # Next primes
    current_prime = 7
    max_product = 5  # Start with the product of primes already collected
    while max_product < 2**1024:  # Enough to cover pw < N
        if not isPrime(current_prime):
            current_prime = nextprime(current_prime)
            continue
        
        # Recover pw mod current_prime
        try:
            pw_mod_r = recover_pw_mod_r(current_prime, c1, c2, N, oracle)
            if pw_mod_r is not None:
                primes.append(current_prime)
                mods.append(pw_mod_r)
                max_product *= current_prime
                print(f"pw mod {current_prime} = {pw_mod_r}")
                print(f"Current max_product = {max_product}")
        except Exception as e:
            print(f"Error with r={current_prime}: {e}")
            break
        
        current_prime = nextprime(current_prime)
    
    # Recover pw via CRT
    if not primes:
        print("No primes collected. Exiting.")
        return
    
    # Use sympy's crt (returns (modulus, remainder))
    crt_result = crt(primes, mods)
    if crt_result is None:
        print("CRT failed (no solution exists). Exiting.")
        return
    
    modulus, pw = crt_result
    print(f"Recovered pw = {pw} (mod {modulus})")
    
    # Verify by checking pw mod each prime matches
    for p, m in zip(primes, mods):
        assert pw % p == m
    
    # Guess pw (since pw could be any pw + k*modulus, we need to find the correct k)
    # Since |guess - pw| < 256, we can try pw, pw + modulus, pw - modulus, etc.
    # But modulus is very large, so likely pw is the smallest positive solution.
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"guess > ", hex(pw)[2:].encode())
    print(r.recvall())

def recover_pw_mod_r(r, c1, c2, N, oracle):
    res = []
    for k in range(1, r):
        if GCD(k, r) != 1:
            continue
        c2_k = (c2 * k) % N
        pt_k = oracle(c1, c2_k)
        inv_k = inverse(k, r)
        pw_mod_r = (pt_k * inv_k) % r
        res.append(pw_mod_r)
        # Early exit if all res are the same
        if len(set(res)) == 1 and len(res) > 1:
            break
    if len(set(res)) != 1:
        print(f"Error: inconsistent results for r={r}, res={res}")
        return None
    return res[0]

if __name__ == "__main__":
    main()