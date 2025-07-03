from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes

server = "ctf.asgama.online"  
port = 10002  

r = remote(server, port)
def encrypt(pt):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b"plaintext = ", str(pt).encode())
    r.recvuntil(b"ciphertext = ")
    return int(r.recvline(0).decode()) 

def main():
    r.sendlineafter(b"> ", b"2")
    r.recvuntil(b"ciphertext = ")
    ct0 = int(r.recvline(0).decode())  

    ct1 = encrypt(ct0)
    secret = str(bytes_to_long(long_to_bytes(ct1)[:128])).encode()

    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b"secret: ", secret)  
    print(r.recv().decode())  
    return 0

if __name__ == "__main__":
    main()
