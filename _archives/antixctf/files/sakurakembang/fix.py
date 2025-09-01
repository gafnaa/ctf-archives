with open("decrypted_flag.png", "rb") as f:
    data = bytearray(f.read())

# Perbaiki byte ke-8 sampai 12 (offset index dimulai dari 0)
data[8:12] = b"\x00\x00\x00\x0D"

with open("fixed_flag.png", "wb") as f:
    f.write(data)