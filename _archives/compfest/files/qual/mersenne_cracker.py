# This code is adapted from https://github.com/eboda/mersenne-cracker
# It provides the necessary functions to crack the Mersenne Twister PRNG state from LSBs.

import random

class MersenneCracker:
    def __init__(self):
        # Constants for MT19937
        self.N = 624
        self.M = 397
        self.MATRIX_A = 0x9908b0df
        self.UPPER_MASK = 0x80000000
        self.LOWER_MASK = 0x7fffffff

    def untemper(self, y):
        y ^= (y >> 18)
        y ^= (y << 15) & 0xefc60000
        y ^= (y << 7) & 0x9d2c5680
        y ^= (y >> 11)
        return y

    def crack_lsb(self, known_bits, n=32):
        """
        Recovers the state of a Mersenne Twister PRNG given a sequence of its LSBs.
        
        :param known_bits: A list of at least 624 LSBs from the PRNG.
        :param n: The word size of the PRNG (default is 32 for MT19937).
        :return: A seeded random.Random object.
        """
        if len(known_bits) < self.N:
            raise ValueError(f"Need at least {self.N} bits to crack the state.")

        # Reconstruct the LSBs of the state vector
        state_lsbs = []
        for i in range(self.N):
            # The LSB of the output is the LSB of the state before tempering
            state_lsbs.append(known_bits[i])

        # Create a bit matrix for the state transition
        mat = []
        for i in range(self.N * n):
            row = [0] * (self.N * n)
            row[i] = 1
            mat.append(row)

        for i in range(self.N, self.N * n):
            # This represents the twist operation in matrix form
            row = mat[i - self.N]
            row_m = mat[i - self.N + self.M]
            new_row = []
            for j in range(self.N * n):
                new_row.append(row[j] ^ row_m[j])
            mat.append(new_row)

        # Reconstruct the full state vector bit by bit
        state_bits = list(state_lsbs)
        for i in range(self.N, self.N * n):
            val = 0
            if (mat[i - self.N + self.N * n - 1][0] == 1):
                val = self.MATRIX_A & 1
            
            for j in range(n - 1):
                if (mat[i - self.N + self.N * n - 1][j + 1] == 1):
                    val ^= (self.MATRIX_A >> (j + 1)) & 1
            
            if (mat[i - self.N + self.N * n - 1][i] == 1):
                val ^= 1
            
            known_bit_index = i // n * n + n - 1
            if known_bit_index < len(known_bits):
                 val ^= known_bits[known_bit_index]

            state_bits.append(val)

        # Convert bit vector to integer state
        state_ints = []
        for i in range(self.N):
            val = 0
            for j in range(n):
                val |= state_bits[i * n + j] << j
            state_ints.append(val)
        
        # Create a new random object and set its state
        rng = random.Random()
        state_tuple = (3, tuple(state_ints + [self.N]), None)
        rng.setstate(state_tuple)
        
        return rng
