from Crypto.Cipher import AES
k1 = b'AA' # Obviously not the actual key
k2 = b'AA' # Obviously not the actual key
message = b'scriptCTF{testtesttesttesttest!_' # Obviously not the actual flag
keys = [k1,k2]
final_keys = []
for key in keys:
    assert len(key) == 2 # 2 byte key into binary
    final_keys.append(bin(key[0])[2:].zfill(8)+bin(key[1])[2:].zfill(8))


cipher = AES.new(final_keys[0].encode(), mode=AES.MODE_ECB)
cipher2 = AES.new(final_keys[1].encode(), mode=AES.MODE_ECB)
enc2 = cipher2.encrypt(cipher.encrypt(message)).hex()

print(enc2)

to_dec = bytes.fromhex(input("Dec: ").strip())

secret = cipher.decrypt(cipher2.decrypt(to_dec))

print(secret.hex())
