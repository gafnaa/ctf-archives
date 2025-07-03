from pwn import *
from Crypto.Util.number import inverse

def try_guess(y_guess):
    # Reconnect every attempt to avoid session timeout
    conn = remote('103.163.139.198', 8042)

    # Get the leaked values
    conn.recvuntil(b'N: ')
    N = int(conn.recvline().strip(), 16)
    conn.recvuntil(b'c1: ')
    c1 = int(conn.recvline().strip(), 16)
    conn.recvuntil(b'c2: ')
    c2 = int(conn.recvline().strip(), 16)

    # Approximate s = h^y ~ 2^y for testing
    try:
        s_guess = pow(2, y_guess, N)
        s_inv = inverse(s_guess, N)
    except ValueError:
        conn.close()
        return False  # Not invertible

    # Calculate pw guess
    pw_guess = (c2 * s_inv) % N

    # Try win
    conn.recvuntil(b'> ')
    conn.sendline(b'3')
    conn.recvuntil(b'guess > ')
    conn.sendline(hex(pw_guess).encode())

    res = conn.recvline(timeout=2)
    if b"Gratz" in res:
        print(f"[🎉] Found! y = {y_guess}")
        print(conn.recvline().decode())  # Print FLAG
        conn.close()
        return True
    else:
        print(f"[-] Failed at y = {y_guess}")
        conn.close()
        return False

# Try guesses for small y
for y in range(256):
    if try_guess(y):
        break
