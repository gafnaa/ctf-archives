import nclib
import numpy as np
import time

def min_path_sum(grid, rows, cols):
    """Menggunakan Dynamic Programming untuk mencari jalur minimum dalam grid."""
    dp = np.zeros((rows, cols), dtype=int)

    # Inisialisasi nilai awal
    dp[0][0] = grid[0][0]

    # Isi baris pertama (hanya bisa dari kiri)
    for j in range(1, cols):
        dp[0][j] = dp[0][j - 1] + grid[0][j]

    # Isi kolom pertama (hanya bisa dari atas)
    for i in range(1, rows):
        dp[i][0] = dp[i - 1][0] + grid[i][0]

    # Isi sisanya (minimalkan sum)
    for i in range(1, rows):
        for j in range(1, cols):
            dp[i][j] = grid[i][j] + min(dp[i - 1][j], dp[i][j - 1])

    return dp[rows - 1][cols - 1]  # Jawaban ada di kanan bawah

def main():
    server = ('94.237.62.255', 30978)
    
    while True:  # Coba reconnect jika perlu
        try:
            print("\n[+] Connecting to server...")
            nc = nclib.Netcat(connect=server)
            nc.settimeout(10)  # Timeout 10 detik untuk menghindari hang
            
            while True:
                # Terima data awal
                try:
                    message = nc.recv_until(b'>', timeout=10).decode().strip()
                except Exception as e:
                    print(f"[!] Timeout/Error: {e}. Reconnecting...")
                    break  # Keluar dari loop dan coba reconnect

                if not message:
                    print("[!] Empty message received. Skipping...")
                    continue

                print("[+] Received:", message)

                # Jika menemukan flag "HTB{", hentikan program
                if "HTB{" in message:
                    print("[🎉] Flag ditemukan! Program berhenti.")
                    exit()

                # Pisahkan semua baris
                lines = message.split("\n")

                # Ambil hanya yang mengandung angka
                numeric_lines = [line for line in lines if line.replace(" ", "").isdigit()]

                if len(numeric_lines) < 2:
                    print("[!] Data tidak cukup, menunggu tambahan...")
                    continue  # Tunggu sampai format data benar

                # Ambil ukuran grid
                try:
                    rows, cols = map(int, numeric_lines[0].split())
                except ValueError:
                    print("[!] Format ukuran grid salah. Skip...")
                    continue

                expected_numbers = rows * cols

                # Ambil angka grid
                numbers = list(map(int, " ".join(numeric_lines[1:]).split()))

                # Jika masih kurang, terima tambahan data
                while len(numbers) < expected_numbers:
                    try:
                        additional_data = nc.recv(timeout=5).decode().strip()
                    except Exception:
                        print("[!] Timeout saat menerima tambahan data. Reconnecting...")
                        break  # Keluar dari loop untuk reconnect

                    if not additional_data:
                        print("[!] Empty additional data. Skipping...")
                        continue

                    print("[+] Received additional data:", additional_data)

                    # Jika flag ditemukan saat menerima tambahan data, hentikan program
                    if "HTB{" in additional_data:
                        print("[🎉] Flag ditemukan! Program berhenti.")
                        exit()

                    numbers.extend(map(int, additional_data.split()))

                # Jika masih kurang, berarti ada masalah dalam penerimaan data
                if len(numbers) != expected_numbers:
                    print(f"[!] Error: Expected {expected_numbers} numbers but got {len(numbers)}. Skipping...")
                    continue

                # Bentuk grid
                grid = [numbers[i * cols:(i + 1) * cols] for i in range(rows)]

                # Hitung minimum path sum
                result = min_path_sum(grid, rows, cols)
                print(f"[+] Sending: {result}")

                # Kirim hasil ke server
                nc.send(f"{result}\n".encode())

                time.sleep(1)  # Hindari spam terlalu cepat

        except Exception as e:
            print(f"[!] Connection error: {e}. Retrying in 5 seconds...")
            time.sleep(5)  # Tunggu sebelum mencoba kembali

if __name__ == '__main__':
    main()
