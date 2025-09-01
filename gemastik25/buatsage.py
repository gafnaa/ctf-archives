#!/usr/bin/env sage

# Import the pwntools library directly
import pwn
from sage.all import *

# Server details
HOST = "18.143.31.243"
PORT = 9055

# Use a context manager for the connection
# This ensures the connection is always closed properly
with pwn.remote(HOST, PORT) as conn:
    # Loop through all 12 rounds
    for i in range(1, 13):
        pwn.log.info(f"--- Solving Round {i}/12 ---")
        
        conn.recvuntil(f"=== Round {i}/12 ===\n".encode())
        
        # --- 1. Parse values and cast to Sage Integers ---
        N = Integer(conn.recvline().strip().split(b" = ")[1])
        conn.recvline() # Skip a/b
        c = Integer(conn.recvline().strip().split(b" = ")[1])
        f = Integer(conn.recvline().strip().split(b" = ")[1])
        conn.recvline() # Skip z
        U1 = Integer(conn.recvline().strip().split(b" = ")[1])
        conn.recvline() # Skip U2

        # --- 2. Implement the cryptographic solution ---
        s_e = U1 % N
        term = (U1 - s_e) // N
        inv_term = term.inverse_mod(N)
        s = ((f - c) * s_e * inv_term) % N
        
        pwn.log.info(f"Calculated s: {s}")
        
        # --- 3. Send the solution ---
        conn.sendlineafter(f"Enter guess for round {i}/12 >> ".encode(), str(s).encode())
        
        # Check the server's response
        response = conn.recvline()
        if b"Nice!" in response:
            pwn.log.success(f"Round {i} correct!")
        else:
            pwn.log.failure(f"Round {i} failed. Response: {response.decode()}")
            exit(1)

    # --- 4. Receive the flag ---
    flag = conn.recvall().strip().decode()
    pwn.log.success(f"Flag: {flag}")