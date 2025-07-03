from pwn import xor

cipher_hex = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
cipher_bytes = bytes.fromhex(cipher_hex)

for key in range(256):
    decoded = xor(cipher_bytes, key)
    try:
        decoded_str = decoded.decode()
        if "crypto" in decoded_str:
            print(f"Key: {key}")
            print(f"Flag: {decoded_str}")
            break
    except:
        continue
