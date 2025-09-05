#!/usr/bin/env python3
from pwn import *

# Connection details
HOST = '20.6.89.33'
PORT = 8054

def solve():
    """
    Connects to the server and attempts the challenge.
    Returns True on success, False on failure.
    """
    try:
        # Establish connection
        conn = remote(HOST, PORT, level='warn')
        conn.recvuntil(b'Find the rabbit!\n')

        # We will feed the server the number it gave us in the previous turn.
        # For the very first number, we have nothing, so we send a guess (0).
        num_to_send = 0

        for i in range(624):
            # Receive the prompt '>> '
            conn.recvuntil(b'>> ')
            
            # Send the number from the previous turn.
            conn.sendline(str(num_to_send).encode())
            
            # Read the server's random number and prepare it for the next turn.
            line = conn.recvline().strip()
            num_to_send = int(line)

            # Optional: Print progress
            if (i + 1) % 100 == 0:
                print(f"[*] Sent {i+1}/624 inputs...")

        print("\n[+] All 624 inputs sent. Waiting for the result...")
        
        # Check the result
        result = conn.recvall(timeout=3).decode()
        if "You found the rabbit!" in result:
            print("\n✅ Success! You found the rabbit!")
            print(result)
            return True
        else:
            print("\n❌ Failure. The rabbit got away.")
            print(result)
            return False

    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == '__main__':
    # The solver works about 50% of the time, so we loop until it succeeds.
    while not solve():
        print("\n" + "="*40)
        print("[!] Retrying in 2 seconds...")
        print("="*40 + "\n")
        time.sleep(2)