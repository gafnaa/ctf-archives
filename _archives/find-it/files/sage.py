from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from binascii import unhexlify

# matrix_bytes = ",".join(map(str, key.list())).encode('utf-8')
# key = sha256(matrix_bytes).digest()

# Sesuaikan dengan iv dan ciphertext dari output
iv = bytes.fromhex("dd389f38c4980b66ac5fd4c9cd5a7484")
ciphertext = bytes.fromhex("a514a4defc7a3c6a1024641231b6fb8b255f234ff6100aff911ff4b5b6a7990f5210c1768977d0dd900e323ab320ed67")

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

print("Flag:", plaintext.decode())
