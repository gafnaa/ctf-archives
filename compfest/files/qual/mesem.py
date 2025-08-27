import os
import subprocess
import sys
from pwn import *
from Crypto.Util.number import bytes_to_long

# --- Step 1: Connect to the server and gather data ---

def get_data_from_server():
    """
    Connects to the challenge server, reads the PRNG outputs and
    the encrypted data, and saves them to files.
    """
    print("[*] Connecting to ctf.compfest.id:7101...")
    # Set a timeout to avoid hanging indefinitely
    context.log_level = 'debug' # Enable verbose logging from pwntools
    conn = None
    try:
        conn = remote('ctf.compfest.id', 7101, timeout=30)
        
        bits = []
        # The server outputs 19968 "even" or "odd" lines
        for i in range(19968):
            line = conn.recvline(timeout=5).strip().decode()
            if "even" in line:
                bits.append(0)
            elif "odd" in line:
                bits.append(1)
            else:
                print(f"\n[!] Unexpected line received: {line}")
                return False
            # Print progress without spamming the console
            print(f"[*] Reading PRNG output: {i+1}/19968", end='\r', flush=True)
        
        print("\n[+] Successfully captured 19968 PRNG bits.")

        # Read the rest of the data (p, n, coeffs, etc.)
        output = conn.recvall(timeout=10).decode()
        
        # Parse the data into a dictionary
        data = {}
        for line in output.strip().split('\n'):
            if ' = ' in line:
                key, value = line.split(' = ', 1)
                try:
                    data[key.strip()] = eval(value)
                except Exception as e:
                    print(f"\n[!] Failed to parse line: {line}\nError: {e}")
                    return False
        
        print("[+] Successfully parsed encrypted data.")
        
        # Save data to be used by the Sage script
        with open('bits.txt', 'w') as f:
            f.write("".join(map(str, bits)))
        
        with open('data.txt', 'w') as f:
            f.write(str(data))
            
        print("[+] Data saved to bits.txt and data.txt.")
        return True

    except Exception as e:
        print(f"\n[!] An error occurred during server communication: {e}")
        return False
    finally:
        if conn:
            conn.close()
        context.log_level = 'info' # Reset log level

# --- Step 2: Create the Sage script for solving ---

def create_sage_script():
    """
    Generates a Sage script that will perform the cryptographic calculations.
    """
    sage_script_content = """
# Import necessary libraries
from Crypto.Util.number import long_to_bytes, bytes_to_long
from mersenne_cracker import MersenneCracker

print("[Sage] Starting solver script.")

# --- Load data from files ---
try:
    with open('bits.txt', 'r') as f:
        bits_str = f.read()
        bits = [int(b) for b in bits_str]

    with open('data.txt', 'r') as f:
        data = eval(f.read())
except FileNotFoundError:
    print("[Sage] Error: data files not found. Please run the Python script first.")
    exit()

p = data['p']
e = data['e']
n = data['n']
coeffs = data['coeffs']
c2_test_noisy = data['c2_test']
c2_secret_noisy = data['c2_secret']

print("[Sage] Data loaded successfully.")

# --- Crack PRNG and predict noise ---
mc = MersenneCracker()
# *** FIX: Use only the first 624 bits to crack the state ***
rng = mc.crack_lsb(bits[:624])
print("[Sage] PRNG state recovered.")

# The script adds noise in this order: c1_test, c2_test, c1_secret, c2_secret
_ = rng.getrandbits(1024) # Noise for c1_test (we don't need it)
noise_c2_test = rng.getrandbits(1024)
_ = rng.getrandbits(1024) # Noise for c1_secret (we don't need it)
noise_c2_secret = rng.getrandbits(1024)
print("[Sage] Noise values predicted.")

# --- Remove noise and recover poly_result ---
c2_test = c2_test_noisy - noise_c2_test
c2_secret = c2_secret_noisy - noise_c2_secret

test_msg = bytes_to_long(b"This is just a test message.")

# Calculate s = c2_test * test_msg^-1 (mod n)
s = (c2_test * pow(test_msg, -1, n)) % n

# Calculate poly_result = c2_secret * s^-1 (mod n)
poly_result = (c2_secret * pow(s, -1, n)) % n
print(f"[Sage] Recovered poly_result.")

# --- Solve the polynomial equation f(m) = 0 mod n ---

# Define the polynomial ring over Z_p to find initial roots
PR_p = PolynomialRing(Zmod(p), 'm')
m_p = PR_p.gen()
f_p = sum(coeffs[i] * m_p^i for i in range(e)) - poly_result
roots_mod_p = f_p.roots(multiplicities=False)

print(f"[Sage] Found {len(roots_mod_p)} root(s) modulo p: {roots_mod_p}")

if not roots_mod_p:
    print("[Sage] No roots found modulo p. Cannot proceed.")
    exit()

# Define the polynomial over integers for Hensel's Lemma
PR_int = PolynomialRing(IntegerRing(), 'm')
m_int = PR_int.gen()
f_int = sum(coeffs[i] * m_int^i for i in range(e)) - poly_result
f_prime = f_int.derivative()

k = 100 # n = p**k

# --- Lift each root from mod p to mod n ---
for m0 in roots_mod_p:
    m0 = int(m0)
    
    # Hensel's Lemma requires f'(root) != 0 mod p
    if f_prime(m0) % p == 0:
        print(f"[Sage] Derivative is zero for root {m0} mod p. Cannot lift with this method.")
        continue

    print(f"[*] Lifting root {m0}...")
    m_lifted = m0
    
    # Iterate from p^1 to p^(k-1)
    for i in range(1, k):
        pi = p**i
        
        f_val = f_int(m_lifted)
        f_prime_val = f_prime(m_lifted)
        
        # The value f(m_lifted) must be divisible by p^i for the lemma to hold
        assert f_val % pi == 0
        
        # Calculate the next term t for the lifting step
        f_prime_inv_p = pow(f_prime_val, -1, p)
        t = (-(f_val // pi) * f_prime_inv_p) % p
        
        # Update the root
        m_lifted = m_lifted + t * pi

    print(f"[+] Lifting complete for root {m0}.")
    
    # Verify the final root and decode the flag
    if f_int(m_lifted) % n == 0:
        print(f"[*] Found valid root mod n: {m_lifted}")
        try:
            flag = long_to_bytes(m_lifted)
            # Check for printable characters
            if all(32 <= c < 127 for c in flag):
                print("========================================")
                print(f"      FLAG: {flag.decode()}")
                print("========================================")
            else:
                print("[-] Decoded bytes are not a printable flag.")
        except Exception as e:
            print(f"[-] Could not convert root to bytes: {e}")
    else:
        print("[-] Lifted root was incorrect.")
"""
    with open("solver.sage", "w") as f:
        f.write(sage_script_content)
    print("[+] Sage script 'solver.sage' created.")

# --- Step 3: Run the Sage script ---

def run_sage_script():
    """
    Executes the generated Sage script using a subprocess call.
    """
    print("[*] Running Sage script... (This may take a moment)")
    try:
        # The 'sage' command must be in your system's PATH
        process = subprocess.run(
            ["sage", "solver.sage"], 
            capture_output=True, 
            text=True, 
            timeout=120 # Add a timeout for the sage script itself
        )
        
        # Always print stdout and stderr to see all messages from Sage
        print("\n--- SAGE OUTPUT START ---")
        print(process.stdout)
        print("--- SAGE OUTPUT END ---")
        
        if process.stderr:
            print("\n--- SAGE ERRORS ---")
            print(process.stderr)
            print("-------------------")

        if process.returncode != 0:
            print(f"\n[!] Sage script exited with a non-zero status code: {process.returncode}")

    except FileNotFoundError:
        print("\n[!] ERROR: 'sage' command not found.")
        print("Please ensure SageMath is installed and the 'sage' command is in your system's PATH.")
    except subprocess.TimeoutExpired:
        print("\n[!] ERROR: Sage script timed out after 120 seconds.")
    except Exception as e:
        print(f"\n[!] An unexpected error occurred while running the Sage script: {e}")

# --- Main execution flow ---

if __name__ == "__main__":
    if not os.path.exists("mersenne_cracker.py"):
        print("[!] Error: 'mersenne_cracker.py' not found.")
        print("Please save the cracker code in the same directory.")
        sys.exit(1)

    if get_data_from_server():
        create_sage_script()
        run_sage_script()
    else:
        print("\n[!] Failed to retrieve data from the server. Aborting.")
        sys.exit(1)
