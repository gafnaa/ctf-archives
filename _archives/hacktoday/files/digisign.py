from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from ecdsa.util import sigencode_der
import os
import ecdsa
import random
import hashlib

FLAG = open("flag.txt", "rb").read()

sk = ecdsa.SigningKey.from_secret_exponent(
    random.getrandbits(128),
    curve=ecdsa.SECP256k1,
    hashfunc=hashlib.sha256
)
vk = sk.get_verifying_key()

print("you need verify yourself first")
print("pubkey.x = ", vk.pubkey.point.x())
print("pubkey.y = ", vk.pubkey.point.y())
msg = int(input("message = "), 16)
r = int(input("r = "), 16)
s = int(input("s = "), 16)
signature = ecdsa.ecdsa.Signature(r, s)
if vk.pubkey.verifies(msg, signature):
    print("Verify Succesfull, Congratulations")
else:
    print("Nope")
    exit(0)
    
privkey = random.getrandbits(32)
sk = ecdsa.SigningKey.from_secret_exponent(
    privkey,
    curve=ecdsa.SECP256k1,
    hashfunc=hashlib.sha256
) 
message = os.urandom(32)
signature = sk.sign(message, sigencode=sigencode_der)

ct = pad(FLAG, AES.block_size)
random.seed(privkey)
for i in range(100000):
    cipher = AES.new(random.randbytes(32), AES.MODE_ECB)
    ct = cipher.encrypt(ct)

print("msg = ", message.hex())
print("signature = ", signature.hex())
print("ct = ", ct.hex())

