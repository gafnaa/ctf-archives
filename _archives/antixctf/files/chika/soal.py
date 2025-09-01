from Crypto.Util.number import *
from random import getrandbits
flag=b"flag{REDACTED}"
class LCG():
	def __init__(self):
		self.a=getrandbits(16)
		self.c=getrandbits(16)
		self.m=getPrime(16)
		self.state=getrandbits(16)%self.m
	def next(self):
		self.state=(self.state*self.a+self.c)%self.m
		return self.state
lcg=LCG()
enc=[]
for i in flag:
	enc.append(i^lcg.next())
print(enc)