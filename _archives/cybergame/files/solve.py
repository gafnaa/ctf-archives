from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
import itertools

# Decode keys
keys = [
    base64.b64decode("h+NvKyaJFRhpn7lRWo0JGGcSk7TOd2ltibSSI1CGDCk="),
    base64.b64decode("CznIYU0rBgmzSb7WyqYfj+WKyDSXbbnsa8Wp/IRvUOc="),
    base64.b64decode("ihpLsXPURUTwH4ULO9/87rHRCQibQO6+V4/QKJL7Bgg=")
]

# Decode ciphertext and IV candidate
ct_b64 = "k8JzsMNxiG5KPGSdM/YjGjW7y8dzgG8vsQ3RB062Kz1/EzwUaWz5Sr2UFNuq0jcWqDdj3Y9I0UKz0rYdZuTxMHZ+oKVEqI8Xv9CuvOmOzkdBoBgsjaWT9ke6+BPcMH9Kpwq/jgoYVQ7SfJDKx5GCAxzSLyyS6tXGIZRrUny6jiU="
y_b64 = "dNMxxcWRHkxNxHu17gw5g5IE/Jf6tNmxw4OfBHEXfRv0cx4pKVKYjZofSRAgFspLnWcdR5GGasKxCgpOANPyS4liypMrPFKlXy/pm2BG7bM="

ciphertext = base64.b64decode(ct_b64)
iv = base64.b64decode(y_b64)[:16]  # First 16 bytes for CBC

def decrypt_ecb(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(data)

def decrypt_cbc(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(data)

for order in itertools.permutations(keys):
    try:
        # Try ECB first (no IV, unpad at the end)
        temp = ciphertext
        for k in order:
            temp = decrypt_ecb(temp, k)
        result = unpad(temp, AES.block_size)
        print("ECB SUCCESS with key order:", order)
        print(result.decode())
        break
    except Exception:
        continue

    try:
        # Try CBC mode
        temp = ciphertext
        for k in order:
            temp = decrypt_cbc(temp, k, iv)
        result = unpad(temp, AES.block_size)
        print("CBC SUCCESS with key order:", order)
        print(result.decode())
        break
    except Exception:
        continue
