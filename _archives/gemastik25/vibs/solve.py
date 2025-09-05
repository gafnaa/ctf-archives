
import sys
import re
from pwn import *

# --- Configuration ---
# Set the host and port from the challenge description.
HOST = "20.6.89.33"
PORT = 8055
# Set the number of rounds for the challenge.
ROUNDS = 12

def solve_challenge():

    conn = remote(HOST, PORT)


    # --- Part 1: Gather Data with a Timeout ---
    log.info("Receiving initial data dump from the server...")
    try:
        # Read data until the server stops sending for 2 seconds.
        # This is more robust than waiting for a specific prompt that might not
        # be part of the initial data dump.
        initial_data = conn.recvrepeat(timeout=2).decode()
        if not initial_data:
            raise EOFError
    except EOFError:
        log.error("Connection closed or no data received from server. Exiting.")
        conn.close()
        return

    log.info("Parsing all 'z' values from the received data...")
    # Use a regular expression to find all occurrences of "z = [number]"
    z_values_str = re.findall(r"z = (\d+)", initial_data)
    
    if len(z_values_str) != ROUNDS:
        log.error(f"Expected {ROUNDS} 'z' values, but found {len(z_values_str)}. Data received:\n{initial_data}")
        conn.close()
        return
        
    guesses = [int(z) for z in z_values_str]
    log.success(f"Successfully parsed {len(guesses)} 'z' values.")

    # --- Part 2: Submit Guesses Interactively ---
    log.info("Starting guess submission process...")
    
    for i in range(1, ROUNDS + 1):
        try:
            # Wait for the prompt for the current round
            prompt = f"Enter guess for round {i}/{ROUNDS} >> ".encode()
            conn.recvuntil(prompt)
            
            # Send the corresponding guess
            current_guess = guesses[i - 1]
            log.info(f"Submitting for round {i}: {current_guess}")
            conn.sendline(str(current_guess).encode())

            # Check the server's response
            response = conn.recvline().strip().decode()
            if "Nice!" in response:
                log.success(f"Server response for round {i}: {response}")
            else:
                log.error(f"Server response for round {i}: {response}")
                log.error("Guess was incorrect. The hypothesis (z=s) may be false.")
                conn.close()
                return

        except EOFError:
            log.error(f"Connection closed unexpectedly while submitting guess for round {i}.")
            conn.close()
            return
            
    log.success("All rounds completed successfully.")
            
    # --- Receive the flag ---
    try:
        # After all correct guesses, the server should send the flag.
        flag = conn.recvall(timeout=2).strip().decode()
        if flag:
            log.success(f"Flag received: {flag}")
        else:
            log.warning("All guesses were correct, but no flag was received.")
    except Exception as e:
        log.critical(f"An error occurred while trying to receive the flag: {e}")
        
    conn.close()

if __name__ == "__main__":
    solve_challenge()

