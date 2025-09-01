from pwn import *
from randcrack import RandCrack
import logging

# --- Configuration ---
HOST = '18.143.31.243'
PORT = 9054

# --- Helper Functions ---
def get_leaked_numbers():
    """
    Connects to the server once to collect the 624 outputs from the
    `random` module. We send dummy inputs (e.g., 0) just to get the
    next output from the server.
    """
    leaked_rands = []
    try:
        # Set a shorter timeout for the initial connection and interactions
        with context.local(timeout=5):
            p = remote(HOST, PORT)
            p.recvuntil(b'Find the rabbit!\n')

            log.info("Collecting 624 leaked random numbers...")
            for i in range(624):
                p.recvuntil(b'>> ')
                p.sendline(b'0')  # Send a dummy value
                line = p.recvline()
                rand_num = int(line.strip())
                leaked_rands.append(rand_num)
            
            p.close()
            log.success("Successfully collected all 624 numbers.")
            return leaked_rands
    except Exception as e:
        log.error(f"Failed to collect numbers: {e}")
        return None

def calculate_required_inputs(leaked_rands):
    """
    Uses RandCrack to reconstruct the internal state of the server's PRNG
    from the leaked outputs. Then, it calculates the sequence of inputs we need
    to send to the server to perfectly clone this state into the 'wack' object.
    """
    if not leaked_rands or len(leaked_rands) != 624:
        log.error("Invalid list of leaked numbers provided.")
        return None

    log.info("Cracking the PRNG state from the collected numbers...")
    cracker = RandCrack()
    for r in leaked_rands:
        cracker.submit(r)
    log.success("PRNG state cracked.")
    
    # After cracking, cracker.mt holds the original internal state array of the
    # server's `random` module. However, its internal index is at the end (624).
    # We reset the index to 0 to make predictions from the beginning of the state.
    cracker.index = 0
    
    required_inputs = []
    log.info("Calculating the 624 correct inputs to send...")
    for _ in range(624):
        # We predict the next 624 outputs. These tempered values are exactly
        # what we need to send to the server. When the server's wack object
        # `submits` (and untempers) them, it will reconstruct the original state.
        required_inputs.append(cracker.predict_getrandbits(32))
    
    log.success("Calculated all required inputs.")
    return required_inputs

def get_flag(required_inputs):
    """
    Connects to the server a second time and sends the carefully calculated
    inputs. This synchronizes the server's two PRNGs, making the 'rabbit'
    value zero and revealing the flag.
    """
    if not required_inputs or len(required_inputs) != 624:
        log.error("Invalid list of required inputs.")
        return

    log.info("Connecting for the final attempt...")
    try:
        p = remote(HOST, PORT)
        p.recvuntil(b'Find the rabbit!\n')
        
        log.info("Preparing and sending the payload...")
        # Combine all inputs into a single payload joined by newlines.
        payload = b'\n'.join(str(num).encode() for num in required_inputs) + b'\n'
        p.send(payload)
        log.success("Payload sent.")

        log.info("Consuming the server's 624 random number outputs...")
        for i in range(624):
            p.recvline() # Read and discard each of the server's intermediate responses.
        log.success("All intermediate outputs consumed.")

        log.info("Waiting for the flag...")
        
        # Now that the intermediate responses are cleared, we can look for the flag.
        p.recvuntil(b'You found the rabbit!\n', timeout=10)
        flag = p.recvline().decode().strip()
        log.success(f"Flag: {flag}")
        
        p.close()
    except Exception as e:
        log.error(f"Failed to get the flag: {e}")

# --- Main Execution ---
if __name__ == "__main__":
    # Configure logging for better output
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    # Step 1: Get the sequence of random numbers from the server
    leaked_numbers = get_leaked_numbers()
    
    if leaked_numbers:
        # Step 2: Calculate the inputs needed to control the server's 'wack' PRNG
        inputs_to_send = calculate_required_inputs(leaked_rands)
        
        if inputs_to_send:
            # Step 3: Connect again and send the correct inputs to get the flag
            get_flag(inputs_to_send)

