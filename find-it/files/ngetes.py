#!/usr/bin/env python3
from pwn import remote
from randcrack import RandCrack
from random import randrange

HOST = 'ctf.find-it.id'
PORT = 6101

def main():
    # Connect and skip the welcome banner
    io = remote(HOST, PORT)
    io.recvline()

    # Read modulus n and public y
    io.recvuntil(b"n = ")
    n = int(io.recvline().strip())
    io.recvuntil(b"y = ")
    y = int(io.recvline().strip())

    # Enter the proof phase by answering choice 1
    io.recvuntil(b"Your choice [1/2]: ")
    io.sendline(b"1")

    # Collect 78 spins (78*256 bits = 624 words) by bailing each time
    rc_input = []
    for i in range(78):
        io.recvuntil(b"Give me an s: ")
        # send a dummy, invertible s
        io.sendline(str(i+2).encode())
        
        io.recvuntil(b"to determine your fate\n")
        b_val = int(io.recvline().strip())
        # split 256-bit into 8×32-bit words
        for j in range(8):
            rc_input.append((b_val >> (32*j)) & 0xffffffff)

        io.recvuntil(b"Your choice [1/2/3]: ")
        # bail inner
        io.sendline(b"2")
        print(i, b_val)
        

    # Reconstruct the MT19937 internal state
    
    rc = RandCrack()
    for word in rc_input:
        rc.submit(word)
    # Cheat the remaining 178 rounds (256 total - 78 collected)
    for _ in range(256 - 78):
        io.recvuntil(b"Give me an s: ")
        # predict next 256-bit spin and extract challenge bit
        b_pred = rc.predict_getrandbits(256)
        c      = b_pred & 1

        # craft z and s so that z^2 ≡ s * y^(1-c) (mod n)
        z   = randrange(1, n)
        inv = pow(pow(y, 1-c, n), -1, n)
        s   = (z*z % n) * inv % n

        # send the calculated s
        io.sendline(str(s).encode())

        io.recvuntil(b"to determine your fate\n")
        real_b = int(io.recvline().strip())
        print(real_b)
        assert real_b == b_pred, "PRNG desync!"

        # answer ready and send z
        io.recvuntil(b"Your choice [1/2/3]: ")
        io.sendline(b"1")
        io.recvuntil(b"Give me a z: ")
        io.sendline(str(z).encode())

        # consume the "convinced" part of the success message
        io.recvuntil(b"convinced")

    # After 256 rounds with passed ≥ 100, the flag is printed
    flag = io.recvuntil(b"}\n", timeout=5)
    print(flag.decode())

if _name_ == "_main_":
    main()