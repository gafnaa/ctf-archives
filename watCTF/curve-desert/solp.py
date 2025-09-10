from pwn import *
from Crypto.Util.number import bytes_to_long, inverse
import ecdsa

HOST = "challs.watctf.org"
PORT = 3788

def get_signature(io, msg):
    io.recvuntil(b"Menu options:")
    io.sendline(b"1")
    io.recvuntil(b"Input hex of message to sign:")
    io.sendline(msg.hex().encode())
    io.recvuntil(b"Your signature is: ")
    data = io.recvline().strip().decode()
    r, s = [int(x) for x in data.split()]
    return r, s

def main():
    io = remote(HOST, PORT)
    # Get challenge
    while True:
        line = io.recvline().decode()
        if "Challenge hex:" in line:
            chal_hex = line.strip().split()[-1]
            challenge = bytes.fromhex(chal_hex)
            break
    print("[*] Challenge:", challenge.hex())

    msg1 = b"hello"
    msg2 = b"world"

    # Get two signatures on different messages
    r1, s1 = get_signature(io, msg1)
    r2, s2 = get_signature(io, msg2)
    assert r1 == r2   # k reused, so r is the same!

    # Curve info
    curve = ecdsa.curves.BRAINPOOLP512r1
    n = curve.order

    # Reconstruct k
    z1 = bytes_to_long(msg1)
    z2 = bytes_to_long(msg2)
    k = ((z1 - z2) * inverse(s1 - s2, n)) % n

    # Reconstruct priv
    priv = ((s1 * k - z1) * inverse(r1, n)) % n

    # Forge signature for challenge
    zc = bytes_to_long(challenge)
    r = r1
    s = (inverse(k, n) * (zc + r * priv)) % n

    # Submit forged signature
    io.recvuntil(b"Menu options:")
    io.sendline(b"2")
    io.recvuntil(b"Input hex of message to verify:")
    io.sendline(challenge.hex().encode())
    io.recvuntil(b"Input the two integers of the signature seperated by a space:")
    signature = f"{r} {s}"
    io.sendline(signature.encode())
    # Get flag
    while True:
        print(io.recvline().decode().strip())

if __name__ == "__main__":
    main()
