import hashlib
import os
from secret import flag
import binascii
from Crypto.Util.number import *
from sympy import *

def gen():
	p=getStrongPrime(1024)
	q=getStrongPrime(1024)
	return p,q

p,q=gen()
n=p*q
e=0x10001
m=bytes_to_long(flag)
ct=pow(m,e,n)

ptambahq=p+q

print(f"n  = {n}")
print(f"e  = {e}")
print(f"ct = {ct}")
print(f"p1tambahq1 = {ptambahq}")
