import base64

def recursive_base64_decode(file_path, keyword='ITFEST{'):
    with open("chall.txt", 'r') as f:
        data = f.read().strip()

    iteration = 0
    while True:
        try:
            decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
            iteration += 1
            print(f"[Iterasi {iteration}] => {decoded[:60]}...")  # Cetak sebagian untuk lihat progres

            if keyword in decoded:
                print("\n✅ Ditemukan string target!")
                print(decoded)
                break

            data = decoded  # Lanjut decode hasilnya
        except Exception as e:
            print(f"\n❌ Gagal decode lebih lanjut. Error: {e}")
            break

# Contoh pemakaian
recursive_base64_decode('encoded.txt')
