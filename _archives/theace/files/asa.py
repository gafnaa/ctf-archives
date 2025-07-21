from Crypto.Cipher import AES
import hashlib
import binascii
from itertools import product

enc_hex = "7d9606e6dcf2f6d441e5e1efd9eb91afc32db2dc233cc1978eb090173eec1de81a5c7bd7a7f3358d35c781dd5cb64d69"
enc = binascii.unhexlify(enc_hex)

# From challenge
target_hash = 0x3d9977528e9d2ce5

print("[*] Brute-forcing full 7-byte keys... This may take time.")

def py2_hash_64bit_emulation(key_bytes):
    # Emulate Python 2.7 hash() behavior on 64-bit
    # This requires actually running Python 2 to precompute a hash -> reverse (not feasible here)
    # So this brute-force avoids hash filtering and tries all keys
    return

for key_tuple in product(range(256), repeat=7):
    key = bytes(key_tuple)
    aes_key = hashlib.sha256(key).digest()
    cipher = AES.new(aes_key, AES.MODE_ECB)
    try:
        pt = cipher.decrypt(enc)
        if pt.startswith(b"ACE{") and all(32 <= x < 127 for x in pt):
            print("[+] Found key:", key)
            print("[+] FLAG:", pt.decode())
            break
    except:
        continue
