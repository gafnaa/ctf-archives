from pwn import *
import random
from math import gcd
from Crypto.Util.number import *

def solve():
    conn = remote('ctf.find-it.id', 6101)
    
    # Get n and y
    conn.recvuntil(b'n = ')
    n = int(conn.recvline().strip())
    conn.recvuntil(b'y = ')
    y = int(conn.recvline().strip())
    
    # Choose "yes"
    conn.sendlineafter(b'Your choice [1/2]: ', b'1')
    
    passed = 0
    while passed < 100:
        # Send a dummy s (will be ignored since we choose option 2 first)
        conn.sendlineafter(b'Give me an s: ', b'2')
        
        # Get b
        conn.recvuntil(b'Let\'s spin the gigantic roulette to determine your fate:\n')
        b = int(conn.recvline().strip())
        
        # Choose option 2 to retry (this allows us to see b before committing to s)
        conn.sendlineafter(b'Your choice [1/2/3]: ', b'2')
        
        # Now compute s based on b
        if b % 2 == 0:
            # Choose random r, set s = r^2 mod n
            r = random.randint(1, n-1)
            while gcd(r, n) != 1:
                r = random.randint(1, n-1)
            s = pow(r, 2, n)
            z = r
        else:
            # Choose random r, set s = r^2 * y^{-1} mod n
            r = random.randint(1, n-1)
            while gcd(r, n) != 1:
                r = random.randint(1, n-1)
            y_inv = pow(y, -1, n)
            s = (pow(r, 2, n) * y_inv) % n
            z = r
        
        # Now send the correct s and z
        conn.sendlineafter(b'Give me an s: ', str(s).encode())
        conn.recvuntil(b'Let\'s spin the gigantic roulette to determine your fate:\n')
        b = int(conn.recvline().strip())
        conn.sendlineafter(b'Your choice [1/2/3]: ', b'1')
        conn.sendlineafter(b'Give me a z: ', str(z).encode())
        
        # Check response
        resp = conn.recvline()
        if b'Good' in resp:
            passed += 1
        else:
            print("Failed!")
            break
    
    # Get flag
    conn.interactive()

solve()