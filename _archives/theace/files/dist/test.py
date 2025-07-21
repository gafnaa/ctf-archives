from pwn import *

flag_bin = open("dist/flag.bin","rb").read()
context.log_level = 'error'

io = process('./viem')
io.sendlineafter(b">> ", b"1")
io.sendlineafter(b"input hex-encoded rom: ", flag_bin.hex().encode())
io.sendlineafter(b">> ", b"2")

flag_enc = io.recvuntil(b"viem executed succesfully", drop=True)

io.sendlineafter(b">> ", b"3")
io.sendlineafter(b">> ", b"4")

assert flag_enc == open("flag.enc", "rb").read(), "ask the author"
assert flag_bin == open("viem.bin", "rb").read(), "ask the author"
print("glhf :)")
