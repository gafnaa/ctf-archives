#!/usr/local/bin/python3
import os
from Crypto.Cipher import AES
import json

N = 16

def load_flag():
    try:
        with open("/flag.txt", "r") as f:
            return f.read().strip()
    except:
        return "fakectf{missing_flag_file}"

def count_blocks(length: int) -> int:
    return (length - 1) // N + 1

def helixlite_padding(message: bytes) -> bytes:
    mlen = len(message)
    blocks = count_blocks(mlen)
    target_len = blocks * N
    if mlen % N == 0:
        target_len += N
    pad_len = target_len - mlen
    return message + bytes([pad_len]) * pad_len

def helixlite_unpad(message: bytes) -> bytes:
    if len(message) < N or len(message) % N != 0:
        raise ValueError("Invalid message length")
    pad_len = message[-1]
    if not (1 <= pad_len <= N):
        raise ValueError("Invalid padding length")
    if message[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding")
    return message[:-pad_len]

def chal():
    FLAG = load_flag()
    k = os.urandom(16)
    m = json.dumps({
        'access_code': FLAG,
        'facility': 'quantum_reactor_z9',
        'clearance': 'alpha'
    }).encode()

    iv = os.urandom(16)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    enc = cipher.encrypt(helixlite_padding(m))
    original = iv + enc

    print(original.hex(), flush=True)
    print("Submit ciphertexts as hex (or type 'quit' to exit):", flush=True)

    while True:
        try:
            line = input("> ").strip()
            if line.lower() in {"quit", "exit", "q"}:
                break

            enc_bytes = bytes.fromhex(line)
            if len(enc_bytes) < 32 or (len(enc_bytes) % 16) != 0:
                print("Invalid data format")
                continue

            if enc_bytes == original:
                print("Valid padding")
                continue

            test_iv, test_ct = enc_bytes[:16], enc_bytes[16:]
            cipher = AES.new(k, AES.MODE_CBC, test_iv)
            pt = cipher.decrypt(test_ct)

            try:
                msg = helixlite_unpad(pt)
                if msg == m:
                    print("Access granted! Flag:", FLAG)
                    break
                else:
                    print("Valid padding")
            except ValueError:
                print("Invalid padding")

        except ValueError:
            print("Parsing error: invalid hexadecimal")
        except KeyboardInterrupt:
            break
        except Exception:
            print("Critical error")

if __name__ == "__main__":
    chal()
