import re
import zlib

def extract_objects(pdf_path):
    with open(pdf_path, 'rb') as f:
        data = f.read()

    # Regex untuk menemukan objek
    obj_regex = re.compile(rb'(\d+)\s+(\d+)\s+obj(.*?)endobj', re.DOTALL)
    matches = obj_regex.findall(data)

    for obj_num, obj_gen, content in matches:
        print(f"\n=== Object {obj_num.decode()} {obj_gen.decode()} ===")

        # Cek apakah objek punya stream
        if b'stream' in content and b'endstream' in content:
            stream_data = content.split(b'stream')[1].split(b'endstream')[0].strip()
            print("[+] Stream detected")

            # Coba decompress jika ada FlateDecode
            if b'/FlateDecode' in content:
                print("[-] FlateDecode detected, attempting decompression...")
                try:
                    decompressed = zlib.decompress(stream_data)
                    print(decompressed.decode(errors='ignore'))
                except Exception as e:
                    print(f"[!] Failed to decompress: {e}")
            else:
                print(stream_data[:200])  # tampilkan sebagian
        else:
            # Kalau tidak ada stream, tampilkan isi objek
            print(content[:500])

if __name__ == '__main__':
    # Ganti nama file sesuai dengan target PDF
    extract_objects("Meeting.pdf")
