import socket
import time

# Daftar nama fungsi yang ingin dicoba
words = [
    "ganyang", "oknum", "kawan", "jalan", "kerja", "tanam", "kita", "ajak", "cangkul", "capek",
    "aman", "rapi", "rajin", "hebat", "niat", "cakap", "cepat", "kompak", "giat", "curiga"
]

HOST = "ctf.find-it.id"
PORT = 7101

for word in words:
    print(f"[!] Mencoba: {word}")
    try:
        with socket.create_connection((HOST, PORT), timeout=5) as s:
            recv = s.recv(4096).decode()
            print(recv)

            # Kirim kata + newline
            s.sendall((word + "\n").encode())

            time.sleep(1)
            recv2 = s.recv(4096).decode()
            print(recv2)

            # Cek apakah output berubah (tidak error biasa)
            if "name" not in recv2 and "Exception" not in recv2:
                print(f"\n[✓] MUNGKIN BERHASIL dengan input: {word}")
                break

    except Exception as e:
        print(f"[!] Error: {e}")
