#!/usr/local/bin/python
import ecdsa, random, os
from Crypto.Util.number import bytes_to_long
curve = ecdsa.curves.BRAINPOOLP512r1
gen = curve.generator
n = curve.order

priv = random.randint(1, n-1)
pub = priv * gen
k = random.randint(1, n-1)


challenge = os.urandom(32)
print('Challenge hex:', challenge.hex())

def sign(msg):
    if msg == challenge:
        print('Try harder than that!')
        exit(1)
    z = bytes_to_long(msg)
    rpoint = k*gen
    r = rpoint.x() % n
    assert r != 0
    s = (pow(k, -1, n) * (z + r*priv)) % n
    return (int(r), int(s))

def verify(msg, r, s):
    z = bytes_to_long(msg)
    u1 = (pow(s, -1, n) * z) % n
    u2 = (pow(s, -1, n) * r) % n
    rpoint = u1*gen + u2*pub
    return rpoint.x() % n == r

assert verify(b'hello', *sign(b'hello'))

def menu():
    print('Menu options:')
    print('[1] Sign')
    print('[2] Verify')
    choice = int(input('Choose an option: ').strip())
    if choice == 1:
        msghex = input('Input hex of message to sign: ').strip()
        r, s = sign(bytes.fromhex(msghex))
        print(f'Your signature is: {r} {s}')
    elif choice == 2:
        msghex = input('Input hex of message to verify: ').strip()
        line = input('Input the two integers of the signature seperated by a space: ').strip()
        r, s = [int(x) for x in line.split(' ')]
        msg = bytes.fromhex(msghex)
        if verify(msg, r, s):
            print('Message verified successfully!')
            if msg == challenge:
                print('You have passed the challenge! Your reward:')
                print(open('flag.txt', 'r').read())
        else:
            print('Invalid signature.')

while True:
    menu()
