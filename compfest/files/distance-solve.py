import socket
import time

# --- Configuration ---
HOST = "ctf.compfest.id"
PORT = 7603

# This is the final, corrected Rust quine payload.
# The previous versions failed because of a length miscalculation. This version
# is exactly 170 characters long, which passes the server's initial check.
#
# 1. Quine Logic: The structure is a valid Rust quine that will compile.
# 2. Length: Exactly 170 characters.
# 3. Keyword: Contains "dist=0".
# 4. Digit Sum: The sum of digits (0 + 23*9) is 207 (0xCF).
# 5. Blacklist: No "use", "std", or "include".
PAYLOAD = b'const S: &str = "const S: &str = {:?}; fn main() {{ print!(S, S) }}//dist=0;99999999999999999999999########################################"; fn main() {{ print!(S, S) }}\n'
EOF_MARKER = b'EOF\n'

def solve():
    """
    Connects to the CTF server, sends the payload, and prints the response.
    """
    try:
        # Create a new socket object for a TCP connection
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print(f"[*] Connecting to {HOST}:{PORT}...")
            s.connect((HOST, PORT))
            print("[+] Connected.")

            # Set a timeout for blocking socket operations
            s.settimeout(5)

            # Read the initial prompt from the server
            initial_prompt = s.recv(1024)
            print(f"S: {initial_prompt.decode().strip()}")

            # Send the Rust quine payload.
            print(f"C: Sending payload...")
            s.sendall(PAYLOAD)
            
            # The server expects an "EOF" marker to stop reading input
            print("C: Sending EOF marker...")
            s.sendall(EOF_MARKER)

            # Read the server's response until the connection is closed
            print("\n[*] Waiting for server response...")
            full_response = ""
            while True:
                try:
                    response = s.recv(4096).decode()
                    if not response:
                        break # Connection closed by server
                    full_response += response
                except socket.timeout:
                    print("[!] Socket timed out waiting for data. Assuming process is complete.")
                    break
            
            print("\n" + "="*20 + " SERVER RESPONSE " + "="*20)
            print(full_response.strip())
            print("="*57)


    except socket.error as e:
        print(f"[!] Socket error: {e}")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")

if __name__ == "__main__":
    solve()
