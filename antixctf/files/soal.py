from Crypto.Util.number import *
flag=b"flag{REDACTED}"
e=0x10001
flag=bytes_to_long(flag)
modulo=getPrime(512)
enc=pow(flag,e,modulo)
print(f'n: {modulo}')
print(f'c: {enc}')