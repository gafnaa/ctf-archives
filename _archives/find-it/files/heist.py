import hmac
import hashlib

auth = 'user:teller|bank:Fortis Bank'
target_sign = '7a91f28871e4b9a78f12ff523f068806d6270aaa418fb2a842135faa68843266'

wordlist = [
    'admin', 'teller', 'fortis', 'fortisbank', 'bank123',
    'key', 'secret', 'supersecret', 'changeme', 'heist', 'flag'
]

for word in wordlist:
    key = word.encode()
    gen_sign = hmac.new(key, auth.encode(), hashlib.sha256).hexdigest()
    if gen_sign == target_sign:
        print(f"[+] Key ditemukan: {word}")
        break
else:
    print("[-] Tidak ditemukan key dari wordlist sederhana.")
