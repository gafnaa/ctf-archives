
from pwn import *

# --- Configuration ---
# Set the host and port for the remote server
HOST = "play.scriptsorcerers.xyz"
PORT = 10300

def solve():
    """
    Connects to the server and exploits the integer division vulnerability
    to find the secret number bit by bit.
    """
    # Establish a connection to the remote server
    conn = remote(HOST, PORT)

    # The problem states the secret is a 128-bit number, which means it's
    # between 2**127 and 2**128 - 1.
    # The most significant bit (127) is always 1.
    # We start with this known fact.
    known_secret = 1 << 127

    log.info("Starting binary search for the secret number...")
    log.info(f"Initial known part (MSB): {known_secret}")

    # We will determine the remaining 127 bits, from bit 126 down to 0.
    for i in range(126, -1, -1):
        # To test the i-th bit, we create a test number by setting that bit
        # in our currently known secret prefix.
        test_number = known_secret + (1 << i)

        # --- Interact with the server ---
        # 1. Choose option [1] to provide a number
        conn.sendlineafter(b"Choice: ", b"1")

        # 2. Send our crafted test number
        conn.sendlineafter(b"Enter a number: ", str(test_number).encode())

        # 3. Read the integer division result 'q'.
        # The server prints the result on a new line after we enter a number.
        q = int(conn.recvline().strip())

        # --- Analyze the result ---
        # The server calculates q = floor(secret / test_number).
        # If q is 1, it means secret >= test_number. This implies that the
        # i-th bit we are testing must be 1.
        if q == 1:
            # Update our known_secret to include the newly found bit.
            known_secret = test_number
            log.info(f"Bit {i} is 1. Current secret: {known_secret}")
        else:
            # If q is 0, it means secret < test_number. This implies that the
            # i-th bit must be 0. We don't need to change known_secret.
            log.info(f"Bit {i} is 0. Current secret: {known_secret}")

    log.success(f"Found the full secret: {known_secret}")

    # --- Submit the final guess ---
    # 1. Choose option [2] to guess the secret
    conn.sendlineafter(b"Choice: ", b"2")

    # 2. Send the fully reconstructed secret number
    conn.sendlineafter(b"Enter secret number: ", str(known_secret).encode())

    # Switch to interactive mode to see the flag
    log.success("Secret sent! Here is the flag:")
    conn.interactive()


if __name__ == "__main__":
    solve()
