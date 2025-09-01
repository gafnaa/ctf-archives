#!/usr/bin/env sage
# -*- coding: utf-8 -*-

from sage.all import *
import itertools
from copy import deepcopy
from pwn import *

# ==============================================================================
# anemoi_utilities.py
# ==============================================================================
def is_mds(m):
    if any(any(r == 0 for r in row) for row in m):
        return False
    N = m.nrows()
    assert m.is_square() and N >= 2
    det_cache = m
    for n in range(2, N + 1):
        new_det_cache = dict()
        for rows in itertools.combinations(range(N), n):
            for cols in itertools.combinations(range(N), n):
                i, *rs = rows
                det = 0
                for j in range(n):
                    c = cols[j]
                    cs = cols[:j] + cols[j + 1:]
                    cofactor = det_cache[(*rs, *cs)]
                    if j % 2 == 1:
                        cofactor = -cofactor
                    det += m[i, c] * cofactor
                if det == 0:
                    return False
                new_det_cache[(*rows, *cols)] = det
        det_cache = new_det_cache
    return True

def get_mds(field, l):
    if l == 1:
        return identity_matrix(field, 1)
    # This is a simplified version for the challenge's specific case (l=1)
    # The full get_mds is not needed.

# ==============================================================================
# anemoi.py
# ==============================================================================
PI_0 = 1415926535897932384626433832795028841971693993751058209749445923078164062862089986280348253421170679
PI_1 = 8214808651328230664709384460955058223172535940812848111745028410270193852110555964462294895493038196

def euler_phi(v):
    if is_prime(v):
        return v - 1
    else:
        factors = factor(v)
        phi = v
        for f in factors:
            phi *= (1 - 1 / f[0])
        return phi

class ANEMOI:
    def __init__(self, q, alpha, nrounds, l):
        self.q = q
        self.alpha = alpha
        self.nrounds = nrounds
        self.l = l
        self.F = GF(self.q)

        if is_prime(self.q):
            if gcd(self.alpha, self.q - 1) != 1:
                raise Exception("alpha should be coprime with phi(q)")
            self.degree = 2
            self.to_field = lambda x: self.F(x)
            self.from_field = lambda x: Integer(x)
        else:
            # Not relevant for this challenge
            pass

        self.g = self.F.multiplicative_generator()
        self.beta = self.g
        self.gamma = 0
        self.delta = self.g ** (-1)
        self.alpha_inv = pow(self.alpha, -1, euler_phi(self.q))

        self.C = []
        self.D = []
        pi_F_0 = self.F(PI_0 % self.q)
        pi_F_1 = self.F(PI_1 % self.q)
        for r in range(0, self.nrounds + 1):
            pi_0_r = pi_F_0 ** r
            self.C.append([])
            self.D.append([])
            for i in range(0, self.l):
                pi_1_i = pi_F_1 ** i
                pow_alpha = (pi_0_r + pi_1_i) ** self.alpha
                self.C[r].append(self.g * (pi_0_r) ** 2 + pow_alpha)
                self.D[r].append(self.g * (pi_1_i) ** 2 + pow_alpha + self.delta)
        
        self.mat = identity_matrix(self.F, 1)

    def __call__(self, X, Y):
        return self.hash([X, Y])

    def hash(self, state):
        for i in range(self.nrounds):
            state = self.forward_round(state, i)
        state = self.add_constants(state, self.nrounds)
        state = self.linear_layer(state)
        return state

    def add_constants(self, state, round_index):
        for i in range(0, self.l):
            state[0][i] += self.C[round_index][i]
            state[1][i] += self.D[round_index][i]
        return state

    def linear_layer(self, state):
        x, y = state[0], state[1]
        x_vec = self.mat * vector(x)
        y_vec = self.mat * vector(y[1:] + y[:1])
        y_vec += x_vec
        x_vec += y_vec
        return [list(x_vec), list(y_vec)]

    def evaluate_sbox(self, _x, _y):
        x, y = _x, _y
        x -= self.beta * y ** self.degree
        y -= x ** self.alpha_inv
        x += (self.beta * y ** self.degree + self.delta)
        return x, y

    def evaluate_sbox_complete(self, state):
        for i in range(0, self.l):
            state[0][i], state[1][i] = self.evaluate_sbox(state[0][i], state[1][i])
        return state

    def forward_round(self, state, round_index):
        state = self.add_constants(state, round_index)
        state = self.linear_layer(state)
        state = self.evaluate_sbox_complete(state)
        return state
    
    # ==========================================================================
    # INVERSE FUNCTIONS FOR THE SOLVER
    # ==========================================================================

    def inv_linear_layer(self, state):
        # M = [[2, 1], [1, 1]] -> M_inv = [[1, -1], [-1, 2]]
        x_out, y_out = state[0][0], state[1][0]
        x_in = x_out - y_out
        y_in = -x_out + 2*y_out
        return [[x_in], [y_in]]
        
    def inv_add_constants(self, state, round_index):
        for i in range(self.l):
            state[0][i] -= self.C[round_index][i]
            state[1][i] -= self.D[round_index][i]
        return state
        
    def inv_sbox(self, x_new, y_new):
        x_tmp = x_new - self.beta * y_new**self.degree - self.delta
        y_old = y_new + x_tmp**self.alpha_inv
        x_old = x_tmp + self.beta * y_old**2
        return x_old, y_old
    
    def inv_sbox_complete(self, state):
        for i in range(self.l):
            state[0][i], state[1][i] = self.inv_sbox(state[0][i], state[1][i])
        return state

    def inverse(self, state):
        state = self.inv_linear_layer(state)
        state = self.inv_add_constants(state, self.nrounds)
        for i in range(self.nrounds - 1, -1, -1):
            state = self.inv_sbox_complete(state)
            state = self.inv_linear_layer(state)
            state = self.inv_add_constants(state, i)
        return state

# ==============================================================================
# CHALLENGE SOLVER
# ==============================================================================

# Challenge parameters
PRIME = 280989701
L = 1
ALPHA = 3
N_ROUNDS = 21
TESTS = 100

def compute_final_state(message, initial_c):
    """
    Computes the full internal state (x,y) of the sponge after hashing.
    """
    state = [[0], [initial_c]]
    perm = ANEMOI(PRIME, ALPHA, N_ROUNDS, L)
    
    # Convert inputs to field elements
    state[0][0] = perm.F(state[0][0])
    state[1][0] = perm.F(state[1][0])
    
    for b in message:
        state[0][0] = state[0][0] + perm.F(b)
        temp_state = deepcopy(state)
        state = perm(temp_state[0], temp_state[1])
    return state

def solve():
    # conn = process(["sage", "chall.py"])  # For local testing
    conn = remote("freestart.challs.snakectf.org", 1337, ssl=True)

    # We need one instance of ANEMOI for our inverse calculations
    P = ANEMOI(PRIME, ALPHA, N_ROUNDS, L)
    
    log.info("Starting challenge...")
    conn.recvuntil(b"MENU:")
    conn.sendline(b"1") # Play

    for i in range(TESTS):
        log.info(f"--- Starting test {i+1}/{TESTS} ---")

        # Parse message and capacity
        conn.recvuntil(b"The chosen message is: ")
        msg_str = conn.recvline().strip().decode()
        message = [int(x) for x in msg_str.strip('[]').split(', ')]
        
        conn.recvuntil(b"The initial capacity is: ")
        initial_capacity = int(conn.recvline().strip())

        log.info(f"Received message: {message}")
        log.info(f"Received capacity: {initial_capacity}")

        # 1. Compute the final state (H, Y) for the given message
        S_final = compute_final_state(message, initial_capacity)
        log.info(f"Computed final state: [{Integer(S_final[0][0])}, {Integer(S_final[1][0])}]")

        # 2. Choose m'2 for our 2-block collision
        m_p2 = P.F(1)

        # 3. Invert the last permutation to get the state before it
        S_pre_p2 = P.inverse(S_final)
        
        # 4. Determine the target output of the first permutation
        X_in = S_pre_p2[0][0]
        Y_in = S_pre_p2[1][0]
        S_post_p1 = [[X_in - m_p2], [Y_in]]
        
        # 5. Invert the first permutation to find our message and capacity
        S_pre_p1 = P.inverse(S_post_p1)
        
        # 6. Extract results and convert from field elements to integers
        m_p1_sol = Integer(S_pre_p1[0][0])
        c_p_sol = Integer(S_pre_p1[1][0])
        m_p2_sol = Integer(m_p2)
        
        colliding_msg = [m_p1_sol, m_p2_sol]
        colliding_cap = c_p_sol
        
        log.success(f"Found colliding message: {colliding_msg}")
        log.success(f"Found colliding capacity: {colliding_cap}")

        # 7. Send the solution to the server
        conn.recvuntil(b"Is there solution? (0 means NO, 1 means YES): ")
        conn.sendline(b"1") # A solution always exists with this method
        
        conn.recvuntil(b"Give me your message: ")
        conn.sendline(f"{m_p1_sol},{m_p2_sol}".encode())
        
        conn.recvuntil(b"Give me your initial capacity: ")
        conn.sendline(str(colliding_cap).encode())
        
        # Check for success message
        response = conn.recvline()
        if b"Congratulations" not in response:
            log.error("Failed test!")
            log.error(response)
            break
        else:
            log.info("Test passed!")
    
    # After 100 successful tests, get the flag
    conn.interactive()


if __name__ == "__main__":
    solve()