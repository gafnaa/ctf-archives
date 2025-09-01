#!/usr/bin/env sage

from Crypto.Hash import SHAKE256
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
from sage.all import GF, inverse_mod
# This script decrypts the output of the Babylon hashing algorithm.
# It reverses the permutation and hashing steps to recover the original flag.

class BabylonDecryptor:
    def __init__(self, digest, iv):
        """
        Initializes the decryptor with parameters matching the encryption script.
        """
        self.exp = 3
        self.p = 65537
        # NOTE: The original script incorrectly calculates nbytes as 2. We keep it
        # here for consistency in all operations.
        self.nbytes = self.p.bit_length() // 8
        self.F = GF(self.p)
        self.state_size = 24
        self.rounds = 3
        self.digest = [self.F(x) for x in digest]
        self.IV = [self.F(x) for x in iv]
        self.genConstants()

    def genConstants(self):
        """
        Generates the same round constants used in the encryption process.
        We must replicate the original script's behavior exactly, which means
        using self.nbytes (2 bytes) to read from the SHAKE stream, even though
        the field size would suggest using 3 bytes.
        """
        shake = SHAKE256.new()
        shake.update(b"SNAKECTF")
        self.constants = []
        for _ in range(self.rounds):
            self.constants.append(self.F(int.from_bytes(shake.read(self.nbytes), 'big')))

    def unshuffle(self, state):
        """
        Reverses the shuffle operation. The shuffle operation is its own inverse.
        """
        # The shuffle is just swapping pairs, so applying it again reverses it.
        for i in range(0, self.state_size, 2):
            t = state[i]
            state[i] = state[i + 1]
            state[i + 1] = t
        return state

    def unadd(self, state, constant):
        """
        Reverses the addition of a round constant.
        """
        return [state[i] - constant for i in range(self.state_size)]

    def unxor(self, a, b):
        """
        Reverses the XOR (field addition) operation.
        """
        return [a[i] - b[i] for i in range(self.state_size)]

    def unsbox(self, state):
        """
        Reverses the S-box operation (modular exponentiation).
        This is done by finding the modular multiplicative inverse of the exponent.
        """
        # The inverse of x^3 is x^d where 3*d = 1 (mod p-1)
        d = inverse_mod(self.exp, self.p - 1)
        return [(state[i])**d for i in range(self.state_size)]

    def unround(self, state, r):
        """
        Reverses a single round of permutation.
        """
        state = self.unadd(state, self.constants[r])
        state = self.unsbox(state)
        return state

    def unpermute(self, state, key):
        """
        Reverses the full permutation process.
        """
        for r in range(self.rounds - 1, -1, -1):
            state = self.unround(state, r)
        state = self.unxor(state, key)
        return state

    def decrypt(self):
        """
        Performs the full decryption to recover the original message.
        The core issue is that for each pair of equations, multiple mathematical
        solutions (roots) can exist. The original script's `break` statement
        caused it to pick the first one it found, which was not always correct.
        This version finds all possible solutions for each pair and then uses a
        depth-first search to find the single sequence of solutions that results
        in a correctly padded plaintext.
        """
        possible_solutions = {}

        for i in range(0, self.state_size, 2):
            di = self.digest[i]
            di1 = self.digest[i+1]
            ki = self.IV[i]
            ki1 = self.IV[i+1]
            
            solutions_for_pair = []
            
            # The original input chunks are from 2 bytes (0-65535).
            # We iterate through all possible values for the first element of the pair.
            for val_i in range(1 << (self.nbytes * 8)):
                xi = self.F(val_i)

                # Calculate P(xi, ki) where P is the permutation function
                p_xi = xi + ki
                for r in range(self.rounds):
                    p_xi = p_xi**self.exp + self.constants[r]
                
                # From d[i] = P(x[i], k[i]) + x[i+1], we derive the potential x[i+1]
                xi1 = di - p_xi

                # The recovered plaintext element must also be a valid 2-byte value.
                if int(xi1) >= (1 << (self.nbytes * 8)):
                    continue

                # Now, verify this pair (xi, xi1) with the second equation:
                # d[i+1] = P(x[i+1], k[i+1]) + x[i]
                p_xi1 = xi1 + ki1
                for r in range(self.rounds):
                    p_xi1 = p_xi1**self.exp + self.constants[r]
                
                if di1 == p_xi1 + xi:
                    solutions_for_pair.append((xi, xi1))

            if not solutions_for_pair:
                print(f"FATAL: Could not find any solution for pair {i}, {i+1}")
                return None
            
            possible_solutions[i] = solutions_for_pair

        # Recursive helper to find the valid path of solutions that unpads correctly.
        def find_valid_path(pair_index, current_path):
            # Base case: if we have built a full-length path, try to unpad it.
            if pair_index >= self.state_size:
                try:
                    padded_bytes = b"".join(long_to_bytes(int(val), self.nbytes) for val in current_path)
                    flag = unpad(padded_bytes, self.state_size * self.nbytes)
                    # If unpad succeeds, we found the correct path.
                    return flag.decode()
                except ValueError:
                    # This path led to incorrect padding.
                    return None

            # Recursive step: try each solution for the current pair and explore.
            for xi, xi1 in possible_solutions[pair_index]:
                result = find_valid_path(pair_index + 2, current_path + [xi, xi1])
                # If a deeper call found a valid flag, propagate it up.
                if result is not None:
                    return result
            
            # No solution was found down this entire branch.
            return None

        # Start the search from the first pair (index 0) with an empty path.
        return find_valid_path(0, [])

if __name__ == "__main__":
    # Data from out.txt
    digest_list = [19620, 45806, 38040, 58887, 43204, 10085, 2201, 50842, 63472, 29122, 25057, 44216, 17185, 1616, 15352, 33058, 14831, 64019, 33816, 6067, 6848, 14403, 10071, 32262]
    IV_list = [33023, 53217, 27554, 51775, 100, 30486, 54599, 9885, 39507, 40305, 21368, 11609, 24968, 7579, 59839, 22818, 20793, 41821, 46152, 16079, 16854, 12663, 38923, 26577]

    decryptor = BabylonDecryptor(digest_list, IV_list)
    flag = decryptor.decrypt()
    
    if flag:
        print("Decryption successful!")
        print(f"Flag: {flag}")
    else:
        print("Decryption failed.")

