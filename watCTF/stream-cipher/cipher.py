import numpy as np, itertools, random

CHUNK_SIZE = 256
shared_key = np.random.permutation(np.arange(CHUNK_SIZE))

def apply_perm(chunk):
    global shared_key
    assert len(chunk) == CHUNK_SIZE
    return np.array(list(chunk), dtype=np.uint8)[shared_key]

def chf(data):
    state = np.zeros(CHUNK_SIZE, dtype=np.uint8)
    for i in range(0, len(data), CHUNK_SIZE):
        chunk = data[i:i+CHUNK_SIZE]
        chunk += b'\0'*(CHUNK_SIZE-len(chunk))
        state ^= apply_perm(chunk)
    return bytes(state.tolist())

def csprng():
    counter = 0
    while True:
        block = chf((1337*str(counter)).encode())
        yield block
        counter += 1

def encrypt(data):
    for enc_block in csprng():
        plain_block = data[:CHUNK_SIZE]
        if len(plain_block) == 0:
            break
        plain_block += b'\0'*(CHUNK_SIZE - len(plain_block))
        cipher_block = bytes([x^y for x,y in zip(plain_block, enc_block)])
        yield cipher_block
        data = data[CHUNK_SIZE:]

with open('AIW.txt', 'rb') as f:
    aiw = f.read()[random.randint(0, 1000):]

with open('encrypted.bin', 'wb') as f:
    for block in encrypt(aiw):
        f.write(block)
