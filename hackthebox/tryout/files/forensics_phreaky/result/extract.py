import zipfile
import os

# Direktori tempat file ZIP berada
zip_dir = ""
password_file = os.path.join(zip_dir, "pw.txt")

# Baca password dari file pw.txt
passwords = {}
with open(password_file, "r") as f:
    for line in f:
        name, pwd = line.strip().split(":")
        passwords[name] = pwd

# Buat folder untuk ekstraksi
extract_dir = os.path.join(zip_dir, "extracted")
os.makedirs(extract_dir, exist_ok=True)

# Ekstrak semua file ZIP
for i in range(1, 16):
    zip_filename = f"part{i}.zip"
    zip_path = os.path.join(zip_dir, zip_filename)

    if zip_filename in passwords:
        password = passwords[zip_filename].encode()

        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            try:
                print(f"[INFO] Mengekstrak {zip_filename} dengan password: {passwords[zip_filename]}")
                zip_ref.extractall(extract_dir, pwd=password)

                # Cek file yang diekstrak
                extracted_files = os.listdir(extract_dir)
                print(f"[INFO] File yang diekstrak dari {zip_filename}: {extracted_files}")

            except RuntimeError:
                print(f"[ERROR] Password salah atau file {zip_filename} rusak!")

print(f"[SUCCESS] Semua file berhasil diekstrak ke folder: {extract_dir}")
