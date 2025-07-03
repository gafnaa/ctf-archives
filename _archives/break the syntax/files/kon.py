import requests

TARGET = "http://ctf.find-it.id:6001"
API_ENDPOINTS = [
    "flag", "secret", "hidden", "debug", "dev", "internal",
    "config", "admin", "private"
]

def try_api(path):
    url = f"{TARGET}/api/{path}"
    print(f"[*] Trying: {url}")
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200 and r.text.strip():
            print(f"[+] FOUND: {url}")
            print("----- RESPONSE -----")
            print(r.text.strip())
            print("--------------------")
            return True
    except Exception as e:
        print(f"[!] Error: {e}")
    return False

def main():
    for path in API_ENDPOINTS:
        if try_api(path):
            return
    print("[-] No hidden API found.")

if __name__ == "__main__":
    main()
