cipher_hex = "65 6c ce 6b c1 75 61 75 61 7e 53 66 c9 52 d8 6c 6a 53 6e 6e de 52 df 63 6d 7e 75 7f ce 64 d5 63 73"
cipher = bytes.fromhex(cipher_hex.replace(" ", ""))

# Known prefix and suffix
flag = ["?"] * len(cipher)
prefix = "ictf{"
suffix = "}"

for i, c in enumerate(prefix.encode()):
    flag[i] = chr(c)
flag[-1] = suffix

# brute-force loop
for i in range(len(flag)):
    if flag[i] != "?":
        continue
    for guess in range(32, 127):  # printable chars
        # XOR check against cipher
        if (guess ^ ord(flag[i % len(flag)])) == cipher[i]:
            flag[i] = chr(guess)
            break

print("Recovered:", "".join(flag))