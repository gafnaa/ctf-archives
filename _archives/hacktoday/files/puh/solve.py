from Crypto.Util.number import long_to_bytes

# The same wordlist used in the encryption script
wordlist = ["puh", "ajarin", "sepuh", "aku", "dong", "mega", "pro", "legend", "top", "noob", "dewa"]

# Create a mapping from word to its index (value in base-11)
word_to_val = {word: i for i, word in enumerate(wordlist)}

def words_to_int(w):
    """Converts a list of 6 words back to an integer."""
    base = 11
    n = 0
    for word in w:
        n = n * base + word_to_val[word]
    return n

def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find gcd and coefficients."""
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def mod_inverse(a, m):
    """Calculates the modular multiplicative inverse of a modulo m."""
    d, x, y = extended_gcd(a, m)
    if d != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def solve_crt(residues, primes):
    """
    Solves the system of congruences using the Chinese Remainder Theorem.
    x ≡ residues[i] (mod primes[i])
    """
    if len(residues) != len(primes):
        raise ValueError("Number of residues must equal number of primes")

    # Calculate N = p1 * p2 * p3 * ...
    N = 1
    for p in primes:
        N *= p

    result = 0
    for r_i, p_i in zip(residues, primes):
        N_i = N // p_i
        y_i = mod_inverse(N_i, p_i)
        result += r_i * N_i * y_i

    return result % N

def main():
    # 1. Read the ciphertext and primes from their files
    with open("cipher.txt", "r") as f:
        cipher_words = f.read().strip().split(' ')
    
    with open("primes.txt", "r") as f:
        primes = [int(p) for p in f.read().strip().split('\n')]

    # 2. Convert words back to integer residues
    residues = []
    for i in range(0, len(cipher_words), 6):
        word_chunk = cipher_words[i:i+6]
        residues.append(words_to_int(word_chunk))

    # 3. Solve for x for each chunk and reconstruct the flag
    flag_bytes = b""
    # Process residues in groups of 3 (one group for each original integer x)
    for i in range(0, len(residues), 3):
        # The set of residues for one number x
        residue_group = residues[i:i+3]
        
        # Solve for x using CRT
        x = solve_crt(residue_group, primes)
        
        # Convert the integer x back to a 4-byte chunk
        flag_bytes += long_to_bytes(x, 4)

    # 4. Decode and remove padding to get the final flag
    flag = flag_bytes.decode('utf-8').rstrip('_')
    
    print("Decryption successful! ✨")
    print(f"The flag is: {flag}")

if __name__ == "__main__":
    main()