from pwn import *
import json
import base64
import codecs
from Crypto.Util.number import long_to_bytes

r = remote('socket.cryptohack.org', 13377)

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

def decode_challenge(enc_type, encoded):
    if enc_type == "base64":
        return base64.b64decode(encoded).decode()
    elif enc_type == "hex":
        return bytes.fromhex(encoded).decode()
    elif enc_type == "rot13":
        return codecs.decode(encoded, 'rot_13')
    elif enc_type == "bigint":
        return long_to_bytes(int(encoded, 16)).decode()
    elif enc_type == "utf-8":
        return ''.join([chr(c) for c in encoded])
    else:
        raise ValueError(f"Unknown encoding type: {enc_type}")

while True:
    received = json_recv()
    
    if "flag" in received:
        print("FLAG:", received["flag"])
        break

    try:
        decoded = decode_challenge(received["type"], received["encoded"])
        json_send({"decoded": decoded})
    except Exception as e:
        print("Decoding failed:", e)
        break
