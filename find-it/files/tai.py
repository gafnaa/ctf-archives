import requests

TARGET = "http://ctf.find-it.id:6001/static/"
FILENAMES = [
    "index.html", "main.js", "app.js", "bundle.js", "flag.txt",
    "secret.js", "config.js", "ctf.js", "admin.js", "hidden.js"
]

def try_static(name):
    url = f"{TARGET}{name}"
    print(f"[*] Trying: {url}")
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200 and "Resource not found" not in r.text:
            print(f"[+] FOUND: {url}")
            print("----- RESPONSE -----")
            print(r.text.strip())
            print("--------------------")
            return True
    except Exception as e:
        print(f"[!] Error: {e}")
    return False

def main():
    for name in FILENAMES:
        if try_static(name):
            return
    print("[-] No interesting file found in /static/")

if __name__ == "__main__":
    main()
