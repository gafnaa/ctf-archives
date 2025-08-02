from PIL import Image
import os

def extract_frames(gif_path, output_folder="frames"):
    # Buat folder output jika belum ada
    os.makedirs(output_folder, exist_ok=True)

    # Buka file GIF
    with Image.open(gif_path) as img:
        frame = 0
        try:
            while True:
                # Simpan setiap frame sebagai PNG
                img.convert("RGBA").save(f"{output_folder}/frame_{frame:03}.png")
                frame += 1
                img.seek(frame)  # Lanjut ke frame berikutnya
        except EOFError:
            print(f"✅ Berhasil mengekstrak {frame} frame ke folder '{output_folder}'.")

if __name__ == "__main__":
    gif_file = "fixed_output.gif"  # Ganti sesuai nama file GIF-mu
    extract_frames(gif_file)
