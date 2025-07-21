import requests
import hashlib
import re
from bs4 import BeautifulSoup

# Konstanta
USERNAME = "Sankyaaku7-"
PASSWORD = "Sankyaaku7-"
LOGIN_URL = "https://ringzer0ctf.com/login"
CHALLENGE_URL = "https://ringzer0ctf.com/challenges/13"

# Buat sesi
session = requests.Session()

# Login tanpa CSRF token
def login():
    print("[*] Logging in...")
    login_data = {
        "username": USERNAME,
        "password": PASSWORD
    }

    response = session.post(LOGIN_URL, data=login_data)
    if "logout" in response.text.lower():
        print("[+] Login sukses.")
    else:
        raise Exception("[-] Login gagal. Periksa username/password atau mungkin perlu CSRF token.")

# Ambil pesan dan hash
def solve_challenge():
    print("[*] Mengakses halaman challenge overview...")
    r = session.get(CHALLENGE_URL, timeout=5)
    soup = BeautifulSoup(r.text, "html.parser")

    challenge_link_tag = soup.find("a", string="Go to this challenge")
    if not challenge_link_tag:
        raise Exception("[-] Tidak bisa menemukan link ke challenge detail.")

    challenge_link = challenge_link_tag["href"]
    print("[*] Mengakses:", challenge_link)

    challenge_resp = session.get(challenge_link, timeout=5)
    message_match = re.search(r"----- BEGIN MESSAGE -----(.*?)----- END MESSAGE -----", challenge_resp.text, re.DOTALL)

    if not message_match:
        raise Exception("[-] Tidak bisa menemukan message.")

    message = message_match.group(1).strip()
    print("[*] Pesan ditemukan. Panjang:", len(message))

    hashed = hashlib.sha512(message.encode()).hexdigest()
    print("[*] SHA512 Hash:", hashed[:20], "...")

    # Gunakan domain yang benar
    base_url = challenge_link
    if base_url.endswith("/"):
        base_url = base_url[:-1]
    submit_url = f"{base_url}/?r={hashed}"

    print("[*] Submit ke:", submit_url)
    submit_resp = session.get(submit_url, timeout=5)

    if "FLAG" in submit_resp.text:
        flag_match = re.search(r"FLAG.*?:\s*([A-Za-z0-9{}_\-]+)", submit_resp.text)
        if flag_match:
            print("[+] Berhasil! FLAG:", flag_match.group(1))
        else:
            print("[+] Submit berhasil, tapi flag tidak ditemukan.")
    else:
        print("[-] Submit gagal atau hash salah.")

# Main
if __name__ == "__main__":
    try:
        login()
        solve_challenge()
    except Exception as e:
        print(e)
