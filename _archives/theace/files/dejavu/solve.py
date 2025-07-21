import random

m = b'A' * 32
cipher = bytes.fromhex("94386abe82c9a8d6d5b14819fd73819f1d8b0a47c9da23395cd01c86a16ef55e")
e = 1234

# XOR untuk dapatkan keystream
keystream = bytes([a ^ b for a, b in zip(cipher, m)])

# Hitung seed
flag_header = b'***THE FLAG DOESNT HAVE FORMAT BTW***'
seed = int.from_bytes(flag_header, 'big') ^ e
print(f"[i] Seed yang dihitung: {seed}")

# GUNAKAN GLOBAL random.seed()
random.seed(seed)

# Generate keystream secara manual
generated = bytes([random.getrandbits(8) for _ in range(len(m))])

# Bandingkan
for i in range(len(keystream)):
    print(f"[{i:02}] keystream: {keystream[i]:02x}, generated: {generated[i]:02x}, match: {keystream[i] == generated[i]}")

if keystream == generated:
    print("[✅] Keystream cocok, PRNG valid (pakai random.seed global).")
else:
    print("[❌] Masih tidak cocok.")
