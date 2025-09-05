from Crypto.Cipher import AES
from Crypto.Util import number

def get_primes_under(n):
    """
    Returns a list of prime numbers less than n.
    This function mirrors the prime generation in the encryption script.
    """
    primes = []
    for p in range(n):
        if number.isPrime(p):
            primes.append(p)
    return primes

def phi(n):
    """
    Calculates Euler's Totient function for an integer n.
    This is a crucial hint for solving the modular exponentiation part.
    Euler's theorem states that if gcd(a, n) = 1, then a^phi(n) ≡ 1 (mod n).
    This can be used to simplify very large exponents.
    You will need to factorize 'n' to calculate this.
    """
    # This is a placeholder. You need to implement the factorization of n
    # and the calculation of phi(n).
    # For a number n = p * q where p and q are prime, phi(n) = (p-1)*(q-1).
    # You can use an online tool or a library to factorize the large number 'n'.
    # Example: If n = 21 (3*7), phi(21) = (3-1)*(7-1) = 2*6 = 12
    return 0 # Replace with your calculated phi(n)

def solve_power_tower(base_list, modulus):
    """
    Solves a power tower (a**(b**(c...))) modulo a number.
    This is the core mathematical puzzle of the challenge.
    
    Example: 2**(3**5) mod n
    
    To solve this, you need to use Euler's Totient Theorem repeatedly.
    The exponent of 'a' should be calculated modulo phi(n).
    The exponent of 'b' should be calculated modulo phi(phi(n)), and so on.
    
    This process is called modular exponentiation reduction.
    """
    if len(base_list) == 1:
        return base_list[0]

    # Recursive step: calculate the exponent for the current base
    exponent = solve_power_tower(base_list[1:], phi(modulus))
    
    # Calculate the final result using modular exponentiation
    # pow(base, exponent, modulus) is efficient for this.
    result = pow(base_list[0], exponent, modulus)
    
    return result

def main():
    # The large number from the script
    n = 107502945843251244337535082460697583639357473016005252008262865481138355040617

    # The ciphertext from the script
    cipher_hex = "b6c4d050dd08fd8471ef06e73d39b359e3fc370ca78a3426f01540985b88ba66ec9521e9b68821fed1fa625e11315bf9"
    ciphertext = bytes.fromhex(cipher_hex)

    # 1. Get the list of primes, same as in the encryption script
    primes = get_primes_under(100)
    print(f"Primes being used: {primes}")

    # --- YOUR TASK ---
    # 2. Calculate the key by solving the power tower modulo n.
    #    - First, you need to factorize 'n' to calculate phi(n).
    #      (Hint: Use an online tool like factordb.com for this large number).
    #    - Then, use the solve_power_tower function with the list of primes.
    #      Remember that the tower is built from the bottom up, so you might
    #      need to reverse the list of primes for the recursive function.
    
    # Let's assume you've figured out the integer key
    # int_key = solve_power_tower(primes_reversed, n) # This is what you need to implement
    
    int_key = 0 # Placeholder for the calculated integer key.
                # You must replace this with the correct value.

    # 3. Convert the integer key to bytes, just like in the encryption script
    if int_key == 0:
        print("\n[INFO] The integer key is not yet calculated.")
        print("Please complete the key calculation steps.")
        key = b'\x00' * 32
    else:
        key = int.to_bytes(int_key, 32, byteorder='big')
        print(f"\nCalculated Key (bytes): {key.hex()}")

    # 4. Decrypt the ciphertext using the derived key
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted_padded = cipher.decrypt(ciphertext)
        
        # The original flag was padded with '_'. We need to remove it.
        decrypted_flag = decrypted_padded.rstrip(b'_')
        
        print(f"\nDecrypted Flag: {decrypted_flag.decode()}")

    except Exception as e:
        print(f"\nDecryption failed. This is expected until the correct key is found.")
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
