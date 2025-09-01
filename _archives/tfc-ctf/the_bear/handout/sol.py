import random
import sys
import time
# It's recommended to install pwntools: pip install pwntools
try:
    from pwn import remote, context
except ImportError:
    print("pwntools not found. Please install it using: pip install pwntools")
    sys.exit(1)

def solve():
    """
    Connects to the challenge server, retrieves the encrypted flag,
    and then brute-forces the PRNG seed to decrypt it.
    """
    
    # --- Step 1: Get the encrypted flag (omlet) from the server ---
    omlet = None
    try:
        # The connection uses SSL/TLS
        print("[*] Connecting to the server...")
        conn = remote('the-bear-74a951c6ebceb302.challs.tfcctf.com', 1337, ssl=True)
        
        # We need to receive data until we see the prompt
        conn.recvuntil(b"Enter your choice: ")
        
        # Choose option "2" to get the flag
        conn.sendline(b"2")
        
        # Receive until the data starts
        conn.recvuntil(b"chat? ")
        
        # Read the line containing the list
        omlet_str = conn.recvline().strip().decode()
        
        conn.close()
        
        # Safely evaluate the string representation of the list
        omlet = eval(omlet_str)
        
        print(f"[+] Successfully received encrypted flag: {omlet}")
        print(f"[+] Length of encrypted flag: {len(omlet)}")

    except Exception as e:
        print(f"[-] Failed to connect or receive data from the server: {e}")
        print(f"[-] Exiting.")
        return

    if not omlet:
        print("[-] Did not receive an encrypted flag. Cannot proceed.")
        return

    # --- Step 2: Brute-force the seed to find the decryption key ---
    flag_len = len(omlet)
    print("\n[*] Previous brute-force failed. Expanding search to a 24-hour window...")
    
    # The random number generator was likely seeded with the system time when the
    # server process started. We'll use the current time as the center of our search.
    base_timestamp = int(time.time())
    print(f"[*] Centering brute-force around current timestamp: {base_timestamp}")

    # Let's check a much wider window of 24 hours (86400 seconds) before the current time
    # and a few seconds after, to account for clock drift or server startup delays.
    search_back = 86400  # 24 hours
    search_forward = 5   # 5 seconds
    print(f"[*] Searching seeds from {base_timestamp - search_back} to {base_timestamp + search_forward}")
    print("[*] This may take a minute...")

    # We search backwards in time from a point slightly in the future.
    total_searches = search_back + search_forward
    for i, timestamp_seed in enumerate(range(base_timestamp + search_forward, base_timestamp - search_back, -1)):
        # Print progress to show the script is working
        if i > 0 and i % 20000 == 0:
            print(f"[*] Searched {i}/{total_searches} seeds...")

        # Seed the random number generator with the timestamp
        random.seed(timestamp_seed)
        
        # Generate the key exactly as the server does
        key = random.choices(range(256), k=flag_len)
        
        # Decrypt the omlet by XORing it with the generated key
        try:
            decrypted_bytes = bytes([omlet[j] ^ key[j] for j in range(flag_len)])
            decrypted_text = decrypted_bytes.decode('ascii')

            # Check if the decrypted text looks like a valid flag
            if decrypted_text.startswith("TFCCTF{") and decrypted_text.endswith("}"):
                print(f"\n[+] Success! Found the flag.")
                print(f"  - Seed (Timestamp): {timestamp_seed}")
                print(f"  - Decrypted Flag: {decrypted_text}")
                return # Exit after finding the flag
        except UnicodeDecodeError:
            # If the bytes don't form valid ASCII, it's not our flag
            continue

    print("\n[-] Failed to find the flag within the tested timestamp range.")


if __name__ == "__main__":
    solve()

