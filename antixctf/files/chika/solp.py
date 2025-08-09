from Crypto.Util.number import isPrime

def solve():
    """
    Solves the LCG-based encryption challenge.

    The encryption is C_i = P_i ^ K_i, where K is the keystream from an LCG.
    The LCG is defined as K_{i+1} = (a * K_i + c) % m.

    This solver exploits the known prefix of the flag ('flag{') to determine the
    first few values of the keystream. With these known values, it can establish
    a relationship between the LCG parameters.

    The core of the attack is to iterate through all possible 16-bit prime moduli 'm'.
    For each 'm', it calculates the corresponding 'a' and 'c' values.
    It then regenerates the full keystream with these parameters to decrypt the
    entire message and checks if the result is the correct flag.
    """
    enc = [7508, 17183, 33829, 41500, 44178, 830, 35278, 40960, 9557, 44195, 33667, 40854, 17646, 11243, 17914, 18095, 24311, 31886, 14739, 7235, 3681, 30258, 15958, 31327, 35702, 15481, 9668, 27666, 44968, 31928, 26438, 23391, 14014, 37011, 4738, 2391, 30250]
    known_plaintext = b'flag{'

    # 1. Recover the first few keystream values using the known plaintext.
    # k_i = enc_i ^ ord(p_i)
    k = [enc[i] ^ known_plaintext[i] for i in range(len(known_plaintext))]
    k1, k2, k3 = k[0], k[1], k[2]

    # 2. From k_{i+1} = (a * k_i + c) % m, we can derive:
    # k3 - k2 = a * (k2 - k1) (mod m)
    # This allows us to find 'a' if we know 'm'.
    diff1 = k2 - k1
    diff2 = k3 - k2

    # 3. Iterate through all possible 16-bit primes for the modulus 'm'.
    # A 16-bit number is between 2^15 and 2^16 - 1.
    print("Searching for the correct LCG parameters...")
    for m in range(2**15, 2**16):
        if not isPrime(m):
            continue

        try:
            # Calculate 'a' using the modular inverse.
            # a = (diff2 * modInverse(diff1, m)) % m
            # pow(x, -1, m) is available in Python 3.8+ for modular inverse.
            a = (diff2 * pow(diff1, -1, m)) % m

            # Calculate 'c' using the LCG equation.
            # c = (k2 - a * k1) % m
            c = (k2 - (a * k1)) % m

            # 4. We have a candidate set (a, c, m). Now, verify it.
            # Generate the full keystream and decrypt the message.
            
            keystream = []
            current_state = k1 # The state after the first output
            keystream.append(current_state)

            for _ in range(len(enc) - 1):
                current_state = (current_state * a + c) % m
                keystream.append(current_state)

            # Decrypt the full message
            decrypted_bytes = b''
            for i in range(len(enc)):
                decrypted_bytes += bytes([enc[i] ^ keystream[i]])
            
            # 5. Check if the decrypted message is the flag.
            if decrypted_bytes.startswith(b'flag{') and decrypted_bytes.endswith(b'}'):
                print("\n[+] Success! Found the correct parameters.")
                print(f"    m = {m}")
                print(f"    a = {a}")
                print(f"    c = {c}")
                print("\n[+] Decrypted Flag:")
                print(f"    {decrypted_bytes.decode()}")
                return

        except ValueError:
            # This occurs if the modular inverse of diff1 does not exist for the current 'm'.
            continue

if __name__ == '__main__':
    solve()
