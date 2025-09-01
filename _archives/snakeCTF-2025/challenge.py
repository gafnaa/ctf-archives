#!/usr/bin/env sage
from Anemoi_primitive.anemoi import *
from copy import deepcopy
import os
import signal
from random import randint

TIMEOUT = 200
FLAG = os.getenv("FLAG", "FLAG{this_is_a_fake_flag_for_testing_purposes}")
PRIME = 280989701


# SPONGE
class SPONGE:
    def __init__(self, prime):
        self.prime = prime
        self.n_bits_per_block = len(bin(prime)[2:]) - 1
        # Anemoi params
        self.l = 1
        self.alpha = 3
        self.n_rounds = 21

    def hash(self, message, initial_c):
        assert initial_c < self.prime
        # ABSORBING PHASE
        state = [[0], [initial_c]]
        for b in message:
            state[0][0] = (state[0][0] + b) % self.prime
            temp = deepcopy(state)
            permutation = ANEMOI(self.prime, self.alpha, self.n_rounds, self.l)
            state = permutation(temp[0], temp[1])
        return state[0][0]


# SERVICE
TEST = 100


def main():
    S = SPONGE(PRIME)
    print("For each of the given messages, you must give me a collision. Let's start!")
    # create message
    print(
        "The messages should be represented as a list of values comma separated such as 2, 3, 4, 5, 6"
    )
    while True:
        print(
            """ 
        MENU:
            1) Play
            2) Exit
            """
        )
        choice = input("> ")
        if choice == "1":
            passed_tests = 0
            while passed_tests < TEST:
                message = [randint(0, PRIME - 1) for _ in range(5)]
                initial_capacity = randint(0, PRIME - 1)
                print(f"The chosen message is: {message}")
                print(f"The initial capacity is: {initial_capacity}")
                hash_value = S.hash(message, initial_capacity)
                print(f"The corresponding hash value is {hash_value}")
                solvable = int(input("Is there solution? (0 means NO, 1 means YES): "))
                if solvable == 0:
                    continue
                elif solvable > 1:
                    break
                input_message = list(
                    map(int, input("Give me your message: ").strip().split(","))
                )
                if len(input_message) < 2:
                    print("Your message must have at least two blocks")
                    break
                if not all([v < PRIME for v in input_message]):
                    print("Your message must be composed of values in the field!")
                    break
                if "|".join(map(str, input_message)) in "|".join(map(str, message)):
                    print("Your message cannot contains subsequences of my message!")
                    break
                input_initial_capacity = int(input("Give me your initial capacity: "))
                your_hash_value = S.hash(input_message, input_initial_capacity)
                if your_hash_value != hash_value:
                    print("The hashes do not match!")
                    break
                else:
                    print("Congratulations!")
                    passed_tests += 1
            if passed_tests == TEST:
                print(f"Congratulations! Here is the flag: {FLAG}")
        elif choice == "2":
            break


if __name__ == "__main__":
    signal.alarm(TIMEOUT)
    main()
