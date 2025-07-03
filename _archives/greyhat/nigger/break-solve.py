from pwn import *

# Encrypted flag from the banner
flag_ct = bytes.fromhex("e77f1fdb96b079b3da8c3b13ca804c528ef38ff166ab6b")

# Try different plaintext lengths to match returned ciphertext
for length in range(20, 33):
    print(f"[*] Trying with known plaintext of length {length}...")

    io = remote("0.cloud.chals.io", 31561)
    io.recvuntil(b"thing:")

    known_pt = b"A" * length
    io.sendline(known_pt)

    try:
        ct_hex = io.recvline(timeout=5).strip().decode()
    except EOFError:
        print("[!] Connection closed unexpectedly.")
        io.close()
        continue

    known_ct = bytes.fromhex(ct_hex)
    io.close()

    if len(known_ct) != length:
        print(f"[-] Mismatch: Sent {length}, got {len(known_ct)} — skipping.")
        continue

    print(f"[+] Match found at length {length}")

    # Recover keystream
    keystream = bytes([a ^ b for a, b in zip(known_pt, known_ct)])

    # Decrypt flag up to available keystream length
    flag_partial = bytes([a ^ b for a, b in zip(flag_ct[:len(keystream)], keystream)])

    print(f"[+] Raw flag bytes: {flag_partial}")
    try:
        print(f"[+] Recovered flag: {flag_partial.decode()}")
    except UnicodeDecodeError:
        print("[!] Couldn't decode as UTF-8. Here is the hex:")
        print(flag_partial.hex())
    break
