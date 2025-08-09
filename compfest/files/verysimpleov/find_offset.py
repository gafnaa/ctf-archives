# find_offset.py
from pwn import *

# Generate a unique pattern of 100 bytes
pattern = cyclic(100)

# Write it to a file
with open('pattern.bin', 'wb') as f:
    f.write(pattern)

print("Pattern written to pattern.bin. Now run GDB.")
