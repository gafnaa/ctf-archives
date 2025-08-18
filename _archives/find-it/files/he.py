import hmac
import hashlib

auth = 'user:teller|bank:Fortis Bank'
target_sign = '7a91f28871e4b9a78f12ff523f068806d6270aaa418fb2a842135faa68843266'

with open('/usr/share/wordlists/rockyou.txt', 'rb') as f:
    for line in f:
        word = line.strip()
        gen_sign = hmac.new(word, auth.encode(), hashlib.sha256).hexdigest()
        if gen_sign == target_sign:
            print(f"[+] Ditemukan key: {word.decode(errors='ignore')}")
            break
