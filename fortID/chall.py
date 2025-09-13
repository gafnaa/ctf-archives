

import base64
from cryptography.fernet import Fernet
import pathlib

# ---------- CONFIG ----------
FLAG = "FakeFlag{makanyajanganflagsharingdek1234_20300320_skfjawophmvjnto3123}"
PASSWORD = "gafna_pw"   # solver must supply this password to get the flag
# This key_str is used exactly the same way as in your example:
# key_base64 = base64.b64encode(key_str.encode())
# You may change it if you want a different distributed file.
KEY_STR = "correctstaplecorrectstaplecorrec"
# ----------------------------

# derive key exactly like the example
key_base64 = base64.b64encode(KEY_STR.encode())
f = Fernet(key_base64)

# plaintext source that will be encrypted and exec()'d in the challenge
plain_source = f"""pw = input('What\\'s the password? ')

if pw == '{PASSWORD}':
    print('{FLAG}')
else:
    print('That password is incorrect.')
"""

# encrypt
token = f.encrypt(plain_source.encode())

# produce a single-file challenge that mirrors your original format
challenge_code = f"""import base64
from cryptography.fernet import Fernet

payload = {repr(token)}

key_str = {repr(KEY_STR)}
key_base64 = base64.b64encode(key_str.encode())
f = Fernet(key_base64)
plain = f.decrypt(payload)
exec(plain.decode())
"""

# write to disk
out = pathlib.Path("challenge.py")
out.write_text(challenge_code, encoding="utf-8")
print(f"Wrote {out.resolve()}")
print("Distribute challenge.py to solvers. They will be asked for a password when running it.")
print()
print("Notes:")
print("- The password that prints the flag is:", PASSWORD)
print("- If you want the key_str or password changed or obfuscated inside challenge.py, tell me and\n  I can modify the generator to split/reverse/xor it so it's not plain text.")
