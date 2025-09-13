# save as solve_shared_prime_rsa.py
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import math
import binascii

# --- paste the two public keys (PEM) here ---
pem1 = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1PtORdHA6pyJn9fU2Gh
grU4v+tPnCX1ji+Dih/qn0ze/NrX3ci21JjCOGp4TW2z24gaCI5MwWWvof89iYQ3
9ZXyw5c5AR1cG7y+HSwC8HASBwlp3zZ62hJmafZd684dWEyUfqUvlggStvWr2BLy
Pr3udlrPvEFoX0t5Ooy/4xAiYM/X9iv9Y8DVvEyOnctWocrVJuFLXHcogINUGgIT
jJ7ol84OXZrG18P1Dqq+KO8qNzrvVb1NNTVjFbC6Jh8d9Zm5onu1jxWQ1pZWz3AB
7aFA+Yl90kEhksECLgXXVJiTm3EFpRHO0nP2VgGHu6ZHZ3D6ay2CXIduO+yqlPK0
oQIDAQAB
-----END PUBLIC KEY-----"""

pem2 = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAubHpZY/hQ0+PIp7UoM1P
npvLsaxxWi3rrZX3lTKbHtTBeN6r84/ahgWuLeS6KOV1P1tGTP5H0GIdWDLqfFa3
ua6s6ZZLghliWF5okQay7WVf/Et84sMyR3wj/rCq7ttu26U72DTeSKlL/hiUqYuj
mHUM1zhRMfgL4iNWQhK3Viv6Cfru+PF9U0awDI8rv2AVkorHe6bIDfkcpKPSjhSB
H409hU8TRVCUNjs7BUMWE1EgdLy/NEChGG+rHUTIptioIYSkUVuGR4PuojEzDtZ2
cOb8Aza3orkMFC4Xt8gRyZJad0/WyJruj9sgURJv6r110qrrCos3F86RsYtl9Uz3
6QIDAQAB
-----END PUBLIC KEY-----"""

# --- ciphertexts as hex (from your challenge) ---
ct1_hex = "59d8a8ce569ce751934d59fa47a9a8f60234e2b299050b3d6a851c6f233fe7692834ce041219930509b8f2841ebbc6af28c5472fc6145a4b934d74e8f8b0d89517c431fe2daaa84578981b995881ed539314a88c8304d229b4cf9bbbf16242fa68c32bca136ff337913b5fa9df14bf32c25acd0b79c4482dad147be04775594a6d176abb431662453725cd45248dc0e3b46de5ba3decf5e3e1d662da68829e67ac69ab6d3f4e7f59c2c587460bdd08d71545a06360f797fd92224aa2ca87f6fc8afc15d5eee114cb5c7c81ba1cc1f7f1654f978976875e6e21ee63bcb4ee5b3235fae45f56b2b10940eda3cad9fe27e1f4104e37599a63d5b297e42a741e3635"
ct2_hex = "9f596fab2148d7fa33465e8ceeca823f61ddda3dc38670569067cbbbde5019da6ec16f36e7c8d11befa5bab6fc783b6bb4894e98f04792089d7b184cb30fd5dbc3e62a4a7bbb804cabb38497c6e5d25ae4d407a565631cc0f3f09a012481cbb5ae4690dadefad7de5c85c5570f693881301274aa64bde4a7ffcb6b357ccb507d58d56e8498ec1c84c380797c5eb8132f8b4db887f2c90992ced9866ec29c1126eef4eea01a926558a4659c67c79c77e01cf5f79ded32f5294d5af5eda40d592e644374833d29dc66f2fd6984d5a2efb4a6dad4f7f55361dc07914bf08ce5183c3133d6b8d33d3229b090f982de66094e280aceca13907d90d174e92cb5a1a168"

# helper to convert ciphertext hex to bytes
ct1_bytes = binascii.unhexlify(ct1_hex)
ct2_bytes = binascii.unhexlify(ct2_hex)

# load public keys
key1 = RSA.import_key(pem1)
key2 = RSA.import_key(pem2)

n1 = key1.n
e1 = key1.e
n2 = key2.n
e2 = key2.e

print("n1 bitlen:", n1.bit_length())
print("n2 bitlen:", n2.bit_length())

# compute gcd to find common prime p
p = math.gcd(n1, n2)
if p == 1:
    raise SystemExit("No common factor found (gcd==1).")
print("found common factor p (decimal):", p)
print("p bitlen:", p.bit_length())

# factor moduli
q1 = n1 // p
q2 = n2 // p
assert p * q1 == n1
assert p * q2 == n2

# compute private exponents
def build_priv(n, e, p, q):
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    # RSA.construct expects (n, e, d, p, q) or (n, e, d)
    priv = RSA.construct((n, e, d, p, q))
    return priv

priv1 = build_priv(n1, e1, p, q1)
priv2 = build_priv(n2, e2, p, q2)

# decrypt with OAEP + SHA-256
cipher1 = PKCS1_OAEP.new(priv1, hashAlgo=SHA256)
cipher2 = PKCS1_OAEP.new(priv2, hashAlgo=SHA256)

pt1 = cipher1.decrypt(ct1_bytes)
pt2 = cipher2.decrypt(ct2_bytes)

print("plaintext 1:", pt1.decode(errors="replace"))
print("plaintext 2:", pt2.decode(errors="replace"))
print("joined:", (pt1 + pt2).decode(errors="replace"))
