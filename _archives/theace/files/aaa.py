from PIL import Image, ImageDraw

# Tentukan ukuran gambar
lebar = 200
tinggi = 100

# Buat gambar baru dengan latar belakang biru
gambar = Image.new('RGB', (lebar, tinggi), 'blue')

# Buat objek untuk menggambar
draw = ImageDraw.Draw(gambar)

# Gambar garis diagonal merah
draw.line((0, 0, lebar, tinggi), fill='red', width=3)

# Simpan gambar ke file
gambar.save('gambar_sederhana.png')

print("Gambar 'gambar_sederhana.png' telah berhasil dibuat!")