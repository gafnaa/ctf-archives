from Crypto.Util.number import *
import random
f=open('flag.png','rb').read()
print(len(f))
key=random.getrandbits(64)
f=[f[i:i+8] for i in range(0,len(f),8)]
f=[bytes_to_long(i) for i in f]
enc=[]
print(len(f))
for i in range(len(f)):
	enc.append(f[i]^key)
print(len(enc))
enc=str(enc)
f2=open('enc','w')
f2.write(enc)
