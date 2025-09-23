from Crypto.Util.strxor import strxor
from secrets import randbelow
from hashlib import sha3_512, sha256
flag=open('flag.txt', 'rb').read()
r=randbelow(2**512)
k=randbelow(2**512)
gs=[randbelow(2**249)*19909 for _ in range(7)]
out=[((k+r*(g^r)))>>64 for g in gs]
ct=strxor(flag,sha3_512(f"{gs};{[r]}".encode()).digest()[:len(flag)])
with open('out3.txt','w+') as f:
    f.write(f'{out=}\n')
    f.write(f'{ct=}\n')
    f.write(f'hint={sha256(f"{r}".encode()).hexdigest()}')