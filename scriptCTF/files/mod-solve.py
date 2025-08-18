#!/usr/bin/env python3
import math
from pwn import *

# --- Configuration ---
HOST = 'play.scriptsorcerers.xyz'
PORT = 10123

def solve():
    """
    Connects to the server and solves the challenge in a single connection
    by exploiting Python's modulo behavior with negative numbers.
    """
    print("[*] Connecting to the server...")
    try:
        # Establish a single connection for the entire process
        conn = remote(HOST, PORT)
        
        # --- Step 1: Send -1 to get (secret - 1) ---
        # In Python, for a positive `secret`, the expression `(-1 % secret)`
        # evaluates to `secret - 1`. This is the core of the solution.
        conn.recvuntil(b'Provide a number: ')
        print("[*] Sending -1 to the server...")
        conn.sendline(b'-1')
        
        # --- Step 2: Read the remainder and calculate the secret ---
        # The line we receive will be the string representation of `secret - 1`.
        line = conn.recvline().strip()
        remainder = int(line)
        print(f"[+] Received remainder: {remainder}")
        
        # Calculate the secret by adding 1 to the remainder.
        secret_guess = remainder + 1
        print(f"[+] Calculated secret guess: {secret_guess}")
        
        # --- Step 3: Send the correct guess ---
        # The server is now waiting for our guess.
        conn.recvuntil(b'Guess: ')
        print("[*] Sending the calculated secret as our guess...")
        conn.sendline(str(secret_guess).encode())
        
        # --- Step 4: Receive and print the flag ---
        print("[+] Guess sent! Awaiting response...")
        response = conn.recvall(timeout=5).decode()
        
        print("\n" + "="*40)
        print("Server Response:")
        print(response)
        print("="*40 + "\n")

        conn.close()
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    # Set the logging level for pwntools to 'error' to keep the output clean
    context.log_level = 'error'
    solve()
