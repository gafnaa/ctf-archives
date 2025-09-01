#!/usr/bin/env python3
import pwn
import ast
import subprocess
import random
import os
import re

# --- Configuration ---
HOST = 'the-bear-74a951c6ebceb302.challs.tfcctf.com'
PORT = 1337
# The Mersenne Twister PRNG (MT19937) used by Python's random module
# has an internal state of 624 32-bit numbers.
NUM_SAMPLES = 624

def solve():
    """
    Main function to orchestrate the decryption process.
    It connects to the server once to ensure all random numbers
    are from the same generator instance.
    """
    print("[*] Starting the decryption process...")
    
    try:
        # Establish a single connection for the entire process
        print(f"[*] Connecting to {HOST}:{PORT} via SSL...")
        conn = pwn.remote(HOST, PORT, ssl=True)

        # --- Step 1: Collect 624 samples from the PRNG ---
        # We need 624 outputs to reconstruct the internal state.
        samples = []
        print(f"[*] Collecting {NUM_SAMPLES} samples to analyze the PRNG state...")
        for i in range(NUM_SAMPLES):
            # Use pwnlib's logging for cleaner output
            pwn.log.info(f"Requesting sample {i + 1}/{NUM_SAMPLES}")
            conn.recvuntil(b"Enter your choice: ")
            conn.sendline(b"1") # Option 1: get_sample()
            conn.recvuntil(b"uhhh here is something but idk what u finna do with it: ")
            sample_str = conn.recvline().strip()
            samples.append(int(sample_str))
        
        pwn.log.success(f"Successfully collected {len(samples)} samples.")

        # --- Step 2: Get the encrypted flag (omlet) ---
        # This must be done in the same connection so it uses the same PRNG state.
        print("[*] Requesting the encrypted flag (omlet)...")
        conn.recvuntil(b"Enter your choice: ")
        conn.sendline(b"2") # Option 2: get_flag()
        conn.recvuntil(b"uhh ig I can give you this if you really want it... chat? ")
        omlet_str = conn.recvline().strip().decode()
        omlet = ast.literal_eval(omlet_str)
        pwn.log.success(f"Received encrypted flag with length {len(omlet)}.")
        
        # We have all the info we need, close the connection
        conn.close()

        # --- Step 3: Crack the PRNG state using untwister ---
        # We feed the collected samples to untwister to find the initial state.
        print("[*] Running 'untwister' to reconstruct the PRNG state from samples...")
        state = crack_state_with_untwister(samples)
        if not state:
            pwn.log.failure("Failed to reconstruct state. Aborting.")
            return

        pwn.log.success("Successfully reconstructed PRNG state.")

        # --- Step 4: Predict the encryption key and decrypt the flag ---
        print("[*] Simulating the server's PRNG to predict the encryption key...")
        
        # Initialize a new random generator with the cracked state
        local_random = random.Random()
        local_random.setstate((3, state, None))

        # Replay the server's actions to synchronize our local PRNG:
        # 1. The 624 calls to get_sample() which each generate a 26-bit number.
        for _ in range(NUM_SAMPLES):
            local_random.getrandbits(26)
            
        # 2. The calls to generate the key. The server uses random.choices(range(256)),
        # which is equivalent to calling randrange(256) for each byte of the key.
        flag_len = len(omlet)
        predicted_key = [local_random.randrange(256) for _ in range(flag_len)]
        
        pwn.log.success("Encryption key predicted successfully.")

        # 3. Decrypt the flag by XORing the omlet with our predicted key.
        flag_chars = [chr(omlet[i] ^ predicted_key[i]) for i in range(flag_len)]
        flag = "".join(flag_chars)

        print("\n" + "="*50)
        pwn.log.success(f"DECRYPTED FLAG: {flag}")
        print("="*50 + "\n")

    except Exception as e:
        pwn.log.failure(f"An error occurred: {e}")

def crack_state_with_untwister(samples):
    """
    Uses the 'untwister' command-line tool to find the PRNG state.
    """
    # Write samples to a temporary file for untwister to read
    temp_filename = "temp_samples.txt"
    with open(temp_filename, "w") as f:
        for s in samples:
            f.write(f"{s}\n")

    try:
        # Command to run untwister. We tell it we have 624 samples,
        # each consisting of the lower 26 bits of the PRNG's output.
        cmd = ["untwister", "--bits", "26", "--count", str(NUM_SAMPLES), "--input", temp_filename]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        
        # Untwister outputs a Python script. We'll parse the state tuple from it.
        # Using a regex is more robust than string splitting.
        match = re.search(r'state = \((.*?)\)', result.stdout, re.DOTALL)
        if not match:
            pwn.log.failure("Could not find state tuple in untwister output.")
            return None
            
        # Safely evaluate the tuple string
        state_tuple_str = f"({match.group(1)})"
        state_tuple = ast.literal_eval(state_tuple_str)
        return state_tuple
        
    except FileNotFoundError:
        pwn.log.failure("'untwister' command not found.")
        pwn.log.info("Please install untwister (e.g., 'sudo apt-get install untwister').")
        return None
    except subprocess.CalledProcessError as e:
        pwn.log.failure(f"Untwister exited with an error: {e.stderr}")
        return None
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_filename):
            os.remove(temp_filename)

if __name__ == "__main__":
    solve()
