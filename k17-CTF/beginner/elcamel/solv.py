#!/usr/bin/env python3
from pwn import *

# Connect to the remote challenge server
io = remote('challenge.secso.cc', 7001)

# Receive the introductory text
io.recvuntil(b'prize...\n\n')

# Read the prime numbers p and q
p = int(io.recvline().strip())
q = int(io.recvline().strip())

# We choose our two distinct numbers, m0 and m1
# Using 0 and 1 is simple and effective
m0 = 0
m1 = 1

# Send our chosen numbers to the server
io.sendlineafter(b'How tall do you want the coin to be?> ', str(m0).encode())
io.sendlineafter(b'How long do you want the coin to be?> ', str(m1).encode())

log.info(f"Using p = {p}")
log.info(f"Using q = {q}")
log.info(f"Sent m0 = {m0}, m1 = {m1}")

# Loop for all 50 rounds of the game
for i in range(50):
    log.info(f"--- Round {i+1}/50 ---")
    
    # Receive the generated number c
    c = int(io.recvline().strip())
    log.info(f"Received c = {c}")

    # --- This is the core logic of the solution ---
    # Test the "Heads" hypothesis (i=0)
    # Calculate (c - m0)^q mod p
    test_val = (c - m0) % p
    check = pow(test_val, q, p)

    # If the result is 1, our guess is Heads. Otherwise, it must be Tails.
    if check == 1:
        guess = b'H'
        log.success("Prediction: Heads (H)")
    else:
        guess = b'T'
        log.success("Prediction: Tails (T)")
    
    # Send our guess to the server
    io.sendlineafter(b'Heads or Tails! (H or T)> ', guess)
    
    # Read the server's response
    response = io.recvline().decode().strip()
    log.info(f"Server response: {response}")
    io.recvline() # Consume the blank line

# After the loop, the server will print the flag if we scored high enough
log.info("Game finished. Receiving the prize...")
io.interactive()