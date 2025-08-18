# Decrypt the provided doc text using the discovered key "oliviarenshaw"
def decrypt_vba_xor(s, key):
    key = key.lower().replace(" ", "")
    out_chars = []
    if len(key) == 0:
        return s
    for i, ch in enumerate(s):
        k = ord(key[i % len(key)])
        out_chars.append(chr((ord(ch) ^ k) ^ 0x7B))
    return "".join(out_chars)

doc = r"""[mlg{gyx#Wzu{n|0Rdjsppw("""

key = "Olivia Renshaw"  # from metadata; code lowercases and strips spaces internally
decrypted = decrypt_vba_xor(doc, key)

print("----- Decrypted document -----\n")
print(decrypted)