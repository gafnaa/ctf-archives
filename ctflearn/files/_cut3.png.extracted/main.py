import binascii

# Hex dump sebagai string multiline (potong dari offset, ambil hanya hex)
hex_dump = """
52 61 72 21 1A 07 00 00 33 92 B5 E5 0A 01 05 06
00 05 01 01 80 80 00 7C BC 22 8D 58 02 03 3C 90
01 04 C1 02 20 67 B8 3D 08 80 03 00 0B 66 31 6E
34 6C 6C 79 2E 74 78 74 30 01 00 03 0F 67 C1 6B
5E EA AD 33 48 01 8F E1 06 A1 A1 B4 9C D8 71 30
D7 3E 87 3B F2 53 BF 05 24 44 2A F9 78 06 4F 48
7A 08 90 21 DC DE 2E 38 B3 0A 03 02 7D 84 A4 66
0F 01 D6 01 14 85 BE 3B 2D 96 5F 8C 4F 57 47 11
B0 87 29 92 F0 43 D1 EE AB 9A 4F 1A 34 08 DC 6A
FD 43 24 38 9F 7C C2 79 94 61 87 67 40 9D 19 6D
F2 B3 43 77 9A A9 F3 26 BA 94 FA 90 88 E7 E1 F3
3F 4F CA 1B 9C CB 4B 5F 56 6B 91 5A 0F 03 75 72
9C 39 49 67 F1 C7 14 99 10 B4 78 CF 6C BB EA E9
90 35 EB 88 BC FF 9A E3 2D 2E EA B2 2C DC C2 81
8F DE 1D B7 A8 AB EA 0D 88 63 8E 80 0E E3 1C 37
92 05 05 65 28 B2 CB 2B D9 FB 67 D0 62 63 BB E7
BE 57 69 4A 1D 77 56 51 03 05 04 00
"""

# Bersihkan string dan gabungkan menjadi satu baris hex
hex_cleaned = ''.join(hex_dump.strip().split())

# Konversi ke biner
binary_data = binascii.unhexlify(hex_cleaned)

# Simpan ke file
with open("fixed_output.rar", "wb") as f:
    f.write(binary_data)

print("[✓] File RAR berhasil dibuat: fixed_output.rar")
