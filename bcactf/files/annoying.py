import os
import zipfile
import shutil

# Ganti dengan nama file ZIP awal Anda
nama_file_awal = 'files/annoying.zip'

# Buat direktori kerja agar file asli tidak tersentuh
direktori_kerja = 'hasil_annoying'
if os.path.exists(direktori_kerja):
    shutil.rmtree(direktori_kerja) # Hapus folder lama jika ada
os.makedirs(direktori_kerja)
shutil.copy(nama_file_awal, direktori_kerja)
os.chdir(direktori_kerja) # Pindah ke direktori kerja

print("Memulai proses ekstraksi otomatis file ZIP...")

# Loop akan terus berjalan selama masih ada file .zip di dalam folder
while True:
    # Cari file .zip yang ada di folder saat ini
    file_zip_ditemukan = None
    for file in os.listdir('.'):
        if file.endswith('.zip'):
            file_zip_ditemukan = file
            break

    if file_zip_ditemukan:
        print(f"Mengekstrak: {file_zip_ditemukan}")
        try:
            # Menggunakan modul zipfile bawaan Python untuk ekstrak
            with zipfile.ZipFile(file_zip_ditemukan, 'r') as zip_ref:
                zip_ref.extractall()

            # Hapus file zip yang sudah diekstrak agar tidak diekstrak lagi
            os.remove(file_zip_ditemukan)
        except zipfile.BadZipFile:
            print(f"Error: {file_zip_ditemukan} bukan file zip yang valid atau rusak.")
            break
        except Exception as e:
            print(f"Terjadi error: {e}")
            break
    else:
        # Jika tidak ada lagi file .zip, hentikan loop
        print("Tidak ada lagi file .zip untuk diekstrak.")
        break

print("\nProses selesai! File terakhir ada di direktori:", direktori_kerja)
print("Isi direktori:")
for file in os.listdir('.'):
    print(f"- {file}")