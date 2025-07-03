import pyshark
import gzip
import io
import re
from pathlib import Path

# Ubah ini ke path file .pcapng kamu
PCAPNG_FILE = 'acap.pcapng'
OUTPUT_GZ_FILE = 'merged_output.gz'

def is_gzip(data):
    # GZIP magic number: 1f 8b
    return data[:2] == b'\x1f\x8b'

def extract_gzip_from_pcapng(pcapng_file):
    print("[*] Membuka file PCAPNG...")
    cap = pyshark.FileCapture(pcapng_file, use_json=True, include_raw=True)
    gzip_chunks = []

    print("[*] Memindai paket...")
    for i, pkt in enumerate(cap):
        try:
            if hasattr(pkt, 'data') and hasattr(pkt.data, 'data'):
                raw_hex = pkt.data.data.replace(':', '')
                raw_bytes = bytes.fromhex(raw_hex)

                if is_gzip(raw_bytes):
                    print(f"[+] GZIP ditemukan di paket ke-{i}")
                    gzip_chunks.append(raw_bytes)
        except Exception as e:
            print(f"[!] Error di paket ke-{i}: {e}")

    print(f"[*] Total GZIP ditemukan: {len(gzip_chunks)}")
    return gzip_chunks

def merge_gzip_chunks(gzip_chunks, output_file):
    print("[*] Menggabungkan file GZIP...")
    with open(output_file, 'wb') as merged_gz:
        for i, chunk in enumerate(gzip_chunks):
            with gzip.GzipFile(fileobj=io.BytesIO(chunk)) as gz_file:
                data = gz_file.read()
                with gzip.GzipFile(fileobj=merged_gz, mode='ab') as out:
                    out.write(data)
    print(f"[+] File hasil gabungan disimpan sebagai: {output_file}")

if __name__ == '__main__':
    gz_chunks = extract_gzip_from_pcapng(PCAPNG_FILE)
    if gz_chunks:
        merge_gzip_chunks(gz_chunks, OUTPUT_GZ_FILE)
    else:
        print("[-] Tidak ditemukan data GZIP dalam file PCAPNG.")
