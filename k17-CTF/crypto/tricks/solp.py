#!/usr/bin/env python3

from pwn import *
from Crypto.Util.number import long_to_bytes

io = remote('challenge.secso.cc', 7005)

io.recvuntil(b"paillier.n = ")
n = int(io.recvline().strip())
c_flag = int(io.recvline().strip())

log.info(f"Received n = {n}")
log.info(f"Received Encrypted Flag = {c_flag}")

n2 = n * n
g = n + 1

def oracle_query(encrypted_x):
    encrypted_y = pow(encrypted_x, 256, n2)
    
    io.sendlineafter(b"Which trick do you want to show me? ", b"cha cha left")
    io.sendlineafter(b"What's the encrypted message you'd like to perform the trick on? ", str(encrypted_x).encode())
    io.sendlineafter(b"What's the encrypted result of the trick? ", str(encrypted_y).encode())
    
    response = io.recvline()
    return b"HOLY SMOKES" in response


low = 0
high = 1 << (32 * 8)
found_flag_val = high # Initialize with a high value

c_flag_inv = pow(c_flag, -1, n2)

log.info("Starting binary search for the flag...")

while low <= high:
    mid = (low + high) // 2
    if mid < low or mid > high: # Safety break for the loop
        break

    c_mid = pow(g, mid, n2)
    c_test = (c_mid * c_flag_inv) % n2
    
    if oracle_query(c_test):
        log.info(f"Oracle says: mid >= F. Search range -> [{low}, {mid - 1}]")
        found_flag_val = mid
        high = mid - 1
    else:
        
        log.info(f"Oracle says: mid < F. Search range -> [{mid + 1}, {high}]")
        low = mid + 1

flag = long_to_bytes(found_flag_val)
log.success(f"Binary search complete! Flag: {flag.decode()}")

io.close()