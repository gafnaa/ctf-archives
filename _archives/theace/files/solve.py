# solve.py - VERSI UNTUK MENYIMPAN KEYSTREAM

import socket

HOST = '117.53.46.98'
PORT = 12000

payload_m_hex = b'00' * 3000
payload_e = b'0'

print("Menghubungi server untuk mendapatkan keystream...")
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(payload_m_hex + b'\n')
        s.sendall(payload_e + b'\n')
        
        full_response = b''
        while len(full_response) < 6000: # 3000 bytes = 6000 hex chars
            chunk = s.recv(4096)
            if not chunk: break
            full_response += chunk
            
    response = full_response.strip()
    keystream = bytes.fromhex(response.decode())

    # Simpan keystream ke file bernama "keystream.bin"
    with open('keystream.bin', 'wb') as f:
        f.write(keystream)
        
    print(f"✅ Berhasil! Keystream ({len(keystream)} bytes) disimpan ke file 'keystream.bin'.")
    print("Lanjutkan ke Langkah 2.")

except Exception as e:
    print(f"❌ Terjadi kesalahan: {e}")
