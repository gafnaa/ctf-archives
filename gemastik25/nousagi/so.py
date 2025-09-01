#!/usr/bin/env python3
import time
from pwn import *

# Connection details
HOST = '20.6.89.33'
PORT = 8054

def solve(initial_guess=0):
    """
    Connects to the server and attempts the challenge with a specific initial guess.
    """
    log.info(f"Attempting challenge with initial guess: {initial_guess}")
    conn = remote(HOST, PORT, level='warn')
    
    try:
        conn.recvuntil(b'Find the rabbit!\n')

        # We will feed the server the number it gave us in the previous turn.
        # For the very first number, we use our strategic guess.
        num_to_send = initial_guess

        for i in range(624):
            conn.recvuntil(b'>> ')
            conn.sendline(str(num_to_send).encode())
            
            line = conn.recvline().strip()
            # Handle potential empty lines or errors from the server
            if not line:
                log.error("Server sent empty response, aborting attempt.")
                return False, -1

            num_to_send = int(line)

        log.info("All 624 inputs sent. Waiting for result...")
        
        # Check the result
        result = conn.recvall(timeout=3).decode()
        
        if "You found the rabbit!" in result:
            print("\n" + "─"*50)
            log.success("Success! You found the rabbit!")
            print(result)
            print("─"*50 + "\n")
            return True, 0
        else:
            # Extract the failed rabbit value for logging
            try:
                rabbit_val = int(result.split(":")[-1].strip())
                log.warning(f"Failed. Rabbit was: {rabbit_val}")
                return False, rabbit_val
            except (ValueError, IndexError):
                log.error("Failed, but couldn't parse Rabbit value.")
                print(result)
                return False, -1

    except Exception as e:
        log.error(f"An error occurred: {e}")
        return False, -1
    finally:
        conn.close()

if __name__ == '__main__':
    max_attempts = 20  # Try up to 20 times, alternating guesses
    guess = 0
    for attempt in range(1, max_attempts + 1):
        log.info(f"--- Attempt #{attempt}/{max_attempts} ---")
        
        # Alternate the guess between 0 and 1
        guess = 1 - guess 
        
        success, rabbit = solve(initial_guess=guess)
        
        if success:
            break
        
        if attempt < max_attempts:
            log.info("Will retry in 2 seconds...")
            time.sleep(2)
    else:
        log.critical("All attempts failed. The server might be down or the strategy needs rethinking.")