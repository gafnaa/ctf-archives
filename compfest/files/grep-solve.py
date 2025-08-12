import struct
import os

def solve():
    """
    Membaca data dari file dump GDB dan merekonstruksi flag.
    """
    KEY_DATA_FILE = 'key_data.bin'
    BINARY_DUMP_FILE = 'binary_dump.bin'
    # Alamat dasar ini sesuai dengan output 'info proc mappings' Anda
    BINARY_BASE_ADDRESS = 0x400000
    EXPECTED_LENGTH = 241

    # Memastikan file-file yang dibutuhkan ada
    if not all(os.path.exists(f) for f in [KEY_DATA_FILE, BINARY_DUMP_FILE]):
        print(f"[-] ERROR: Pastikan file '{KEY_DATA_FILE}' dan '{BINARY_DUMP_FILE}' ada di direktori yang sama.")
        return

    # 1. Baca data dari kedua file dump
    with open(KEY_DATA_FILE, 'rb') as f:
        key_data_raw = f.read()
    
    with open(BINARY_DUMP_FILE, 'rb') as f:
        binary_dump = f.read()

    print(f"[+] Berhasil memuat {len(key_data_raw)} byte dari '{KEY_DATA_FILE}'.")
    print(f"[+] Berhasil memuat {len(binary_dump)} byte dari '{BINARY_DUMP_FILE}'.")

    # 2. Parse tabel pointer dari key_data.bin (format: 64-bit little-endian)
    qwords = struct.unpack(f'<{len(key_data_raw)//8}Q', key_data_raw)
    
    # Ambil hanya pointer-nya saja (setiap elemen ke-0, 2, 4, ...)
    base_pointers = qwords[::2]

    flag = bytearray()

    print("[+] Merekonstruksi flag...")
    for i in range(EXPECTED_LENGTH):
        # 3. Terapkan logika verifikasi dari program
        # offset = i XOR 23 (atau 0x17 dalam hex)
        index_offset = i ^ 0x17
        
        # Ambil base pointer untuk iterasi saat ini
        base_ptr = base_pointers[i]
        
        # Hitung alamat virtual dari karakter flag
        char_virtual_address = base_ptr + index_offset
        
        # 4. Konversi alamat virtual ke offset file
        file_offset = char_virtual_address - BINARY_BASE_ADDRESS
        
        try:
            # Baca satu byte dari dump memori pada offset yang dihitung
            flag_char = binary_dump[file_offset]
            flag.append(flag_char)
        except IndexError:
            print(f"\n[-] GAGAL: Tidak bisa membaca dari offset file {hex(file_offset)} untuk indeks {i}.")
            print("    Pastikan alamat dasar dan alamat akhir yang Anda gunakan untuk dump sudah benar.")
            return

    print("\n[+] BERHASIL! Flag telah direkonstruksi:")
    # Cetak flag sebagai string
    print(flag.decode('utf-8'))


if __name__ == '__main__':
    solve()
