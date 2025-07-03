from scapy.all import *
import gzip
import io
import os

# Ganti dengan path file .pcapng kamu
pcap_file = "acap.pcapng"

# File output gabungan
output_gzip = "combined_output.gz"

# List untuk menyimpan semua data gzip
gzip_chunks = []

# Fungsi untuk mendeteksi apakah data adalah gzip
def is_gzip(data):
    return data.startswith(b'\x1f\x8b')

# Membaca paket-paket dari file pcapng
packets = rdpcap(pcap_file)

for packet in packets:
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        if is_gzip(payload):
            gzip_chunks.append(payload)

# Gabungkan semua data gzip ke dalam satu file
with gzip.open(output_gzip, "wb") as f_out:
    for i, chunk in enumerate(gzip_chunks):
        try:
            # Decompress masing-masing chunk
            decompressed = gzip.decompress(chunk)
            f_out.write(decompressed)
        except Exception as e:
            print(f"[!] Chunk {i} gagal didekompresi: {e}")

print(f"[✓] Berhasil mengekstrak dan menggabungkan {len(gzip_chunks)} file gzip ke: {output_gzip}")
