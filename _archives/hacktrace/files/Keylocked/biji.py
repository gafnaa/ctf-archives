# Potongan data pertama yang Anda temukan
chunkA = bytes([
    0x68, 0x12, 0x13, 0x1e, 0x19, 0x6a, 0x68, 0x6f, 0x21, 0x6b, 0x29, 0x05, 
    0x28, 0x3f, 0x2c, 0x69, 0x28, 0x29, 0x69
])

# Potongan data kedua yang Anda temukan
chunkB = bytes([
    0x05, 0x37, 0x6e, 0x36, 0x2d, 0x1b, 0x28, 0x1f, 0x05, 0x1f, 0x3b, 0x09, 
    0x23, 0x23, 0x23, 0x65, 0x65, 0x27
])

# Daftar urutan yang diekstrak dari data hex terakhir
# Terdiri dari 37 angka (dari 1 sampai 36, dan terakhir 0)
order = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 0
]

# --- Logika Dekripsi ---

# 1. Gabungkan kedua potongan data
combined_data = chunkA + chunkB
flag_bytes = []

# 2. Susun ulang byte berdasarkan daftar 'order'
# Karena array di Python dimulai dari 0, kita tidak perlu mengubah angkanya
for index in order:
    if index < len(combined_data):
        flag_bytes.append(combined_data[index])

# 3. Ubah byte yang sudah diurutkan menjadi teks
flag = bytes(flag_bytes).decode('utf-8', errors='ignore')

# 4. Tampilkan hasilnya
print("="*40)
print("FLAG DITEMUKAN:", flag)
print("="*40)