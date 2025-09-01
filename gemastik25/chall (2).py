import sys, signal
from secrets import randbelow
from math import gcd
from Crypto.Util.number import getPrime, inverse
import random

rbits = lambda x: random.getrandbits(x)
R=12;BITS=1024;M_BITS=5680;TIME=120;GOAT=910
signal.signal(signal.SIGALRM,lambda *_:(print("timeout"),sys.exit(1)))
signal.alarm(TIME)
M1 = randbelow(1<<M_BITS) or 1
ss = []

def one_round(i):
    p,q=getPrime(BITS),getPrime(BITS)
    N=p*q
    a,b,c=rbits(GOAT),rbits(GOAT),rbits(GOAT)
    g=gcd(a, b)
    a//=g
    b//=g
    phi=(p**3-a)*(q**3-b)
    d=getPrime(BITS)
    e=inverse(d,phi)
    f=e*M1+c
    s=randbelow(N-2)
    m2=M1*a+b
    z=pow(s,e*d,N)
    U1=pow(s+M1*N,e,N*N)
    U2=pow(s+m2*N,d,N*N)
    print(f"=== Round {i}/{R} ===")
    print(f"N = {N}")
    print(f"a/b = {(a * pow(b, -1, N)) % N}")
    print(f"c = {c}")
    print(f"f = {f}")
    print(f"z = {z}")
    print(f"U1 = {U1}")
    print(f"U2 = {U2}")
    ss.append(s)

for i in range(1,R+1):one_round(i)
for i in range(1,R+1):
    g = int(input(f"Enter guess for round {i}/{R} >> "))
    if g == ss[i-1]: print("Nice!")
    else:
        print("Fail!")
        exit(1)
print(open("flag.txt").read().strip())
