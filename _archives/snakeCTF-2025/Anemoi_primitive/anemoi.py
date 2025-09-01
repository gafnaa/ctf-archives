from sage.all import *
from Anemoi_primitive.anemoi_utilities import *
from copy import deepcopy

"""
Simple ANEMOI implementation
"""

"""
Constants from https://github.com/anemoi-hash/anemoi-hash
"""
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


"""
Simple ANEMOI in F_q^2l
"""


class ANEMOI:
    def __init__(self, q, alpha, nrounds, l):
        self.q = q
        self.alpha = alpha
        self.nrounds = nrounds
        self.l = l

        # generate the field
        self.F = GF(self.q)

        if is_prime(self.q):
            if gcd(self.alpha, self.q - 1) != 1:
                raise Exception("alpha should be coprime with phi(q)")

            self.degree = 2
            self.to_field = lambda x: self.F(x)
            self.from_field = lambda x: Integer(x)
        else:
            self.degree = 3
            self.to_field = lambda x: self.F.fetch_int(x)
            self.from_field = lambda x: x.integer_representation()

        # get the generator and the inv_generator
        self.g = self.F.multiplicative_generator()
        self.beta = self.g
        self.gamma = 0
        self.delta = self.g ** (-1)
        self.alpha_inv = pow(alpha, -1, euler_phi(self.q))

        # Choosing constants: self.C and self.D are built from the
        # digits of pi using an open butterfly
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

        self.mat = get_mds(self.F, self.l)

    """
        X, Y: lists of l values in F_q
    """

    def __call__(self, X, Y):
        if len(X) != self.l or len(Y) != self.l:
            raise Exception("wrong input size!")
        else:
            return self.hash([X, Y])

    """
    :param state is a list of 2*l values in F_q
    """

    def hash(self, state):
        for i in range(self.nrounds):
            state = self.forward_round(state, i)

        state = self.add_constants(state, self.nrounds)
        state = self.linear_layer(state)
        return state

    def verify(self, state, hash):
        return None

    """
    param: state -> list of elements in F_q
    """

    def add_constants(self, state, round_index):
        # pick the constants depending on alpha
        temp_state = deepcopy(state)

        for i in range(0, self.l):
            state[0][i] += self.C[round_index][i]
            state[1][i] += self.D[round_index][i]

        return state

    def linear_layer(self, state):
        x, y = state[0], state[1]
        x = self.mat * vector(x)
        y = self.mat * vector(y[1:] + [y[0]])
        # Pseudo-Hadamard transform on each (x,y) pair
        y += x
        x += y
        return [list(x), list(y)]

    def evaluate_sbox(self, _x, _y):
        x, y = _x, _y
        x -= self.beta * y ** self.degree
        y -= x ** self.alpha_inv
        x += (self.beta * y ** self.degree + self.delta)
        return x, y

    def evaluate_sbox_complete(self, state):
        """ Flystel evaluation """
        """Applies an open Flystel to the full state. """
        temp_state = deepcopy(state)
        for i in range(0, self.l):
            temp_state[0][i], temp_state[1][i] = self.evaluate_sbox(temp_state[0][i], temp_state[1][i])

        return temp_state

    def forward_round(self, state, round_index):
        state = self.add_constants(state, round_index)
        state = self.linear_layer(state)
        state = self.evaluate_sbox_complete(state)
        return state
