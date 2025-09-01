#!/usr/bin/env python3

import sys
from os import path
from random import randint
from hashlib import sha256

P = 112100829556962061444927618073086278041158621998950683631735636667566868795947
ROUNDS = randint(26, 53)
CONSTANT = [(44 * i ^ 3 + 98 * i ^ 2 + 172 * i + 491) % P for i in range(ROUNDS)]
EXPONENT = 3


def split(x):
    chunk1 = x // P
    chunk2 = x % P
    return chunk1, chunk2


def merge(chunk1, chunk2):
    return chunk1 * P + chunk2


def ff(x):
    return ((x * EXPONENT) * 0x5DEECE66D) % P


def gg(x):
    digest = sha256(int(x).to_bytes(256)).digest()
    return int.from_bytes(digest) % P


def transform(x, y, i):
    u = x
    if i % 11 == 0:
        v = (y + ff(u)) % P
    else:
        v = (y + gg(u)) % P
    v = (v + CONSTANT[i]) % P
    return v, u


def encrypt(input):
    chunk1, chunk2 = split(input)
    for i in range(ROUNDS):
        if i % 5 == 0:
            chunk1, chunk2 = transform(chunk1, chunk2, i)
        else:
            chunk2, chunk1 = transform(chunk2, chunk1, i)
    output = merge(chunk1, chunk2)
    return output


if __name__ == "__main__":
    out_dir = sys.argv[1]
    flag = sys.argv[2].encode()

    input = int.from_bytes(flag)
    ciphertext = encrypt(input)

    with open(path.join(out_dir, "out.txt"), "w") as f:
        f.write(hex(ciphertext))
