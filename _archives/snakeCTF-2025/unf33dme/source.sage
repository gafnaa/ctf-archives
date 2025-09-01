#!/usr/bin/env sage

import sys
from os import path

from Crypto.Hash import SHAKE256
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long


class Babylon:
    def __init__(self):
        self.setParams()
        self.genConstants()

    def setParams(self):
        self.exp = 3
        self.p = 65537
        self.nbytes = self.p.bit_length() // 8
        self.F = GF(self.p)
        self.state_size = 24
        self.rounds = 3

    def genConstants(self):
        shake = SHAKE256.new()
        shake.update(b"SNAKECTF")
        self.constants = []
        for _ in range(self.rounds):
            self.constants.append(self.F(int.from_bytes(shake.read(self.nbytes), 'big')))

    def decompose(self, message):
        state = []
        padded_message = pad(message, self.state_size * self.nbytes)
        for i in range(0, len(padded_message), self.nbytes):
            chunk = bytes_to_long(padded_message[i:i + self.nbytes])
            state.append(chunk)
        return state

    def random(self):
        return [self.F.random_element() for _ in range(self.state_size)]

    def shuffle(self, state):
        for i in range(0, self.state_size, 2):
            t = state[i]
            state[i] = state[i + 1]
            state[i + 1] = t
        return state

    def add(self, state, constant):
        return [state[i] + constant for i in range(self.state_size)]

    def xor(self, a, b):
        return [a[i] + b[i] for i in range(self.state_size)]

    def sbox(self, state):
        return [(state[i]) ^ self.exp for i in range(self.state_size)]

    def round(self, state, r):
        state = self.sbox(state)
        state = self.add(state, self.constants[r])
        return state

    def permute(self, state, key):
        state = self.xor(state, key)
        for r in range(self.rounds):
            state = self.round(state, r)
        return state

    def hash(self, message):
        input = self.decompose(message)
        IV = self.random()
        output = self.permute(input, IV)
        digest = self.xor(output, self.shuffle(input))
        return digest, IV


if __name__ == "__main__":
    out_dir = sys.argv[1]
    flag = sys.argv[2].encode()

    babylon = Babylon()
    assert len(flag) < babylon.state_size * babylon.nbytes, len(flag)

    digest, IV = babylon.hash(flag)

    with open(path.join(out_dir, "out.txt"), "w") as f:
        f.write(f"{digest}\n{IV}")
