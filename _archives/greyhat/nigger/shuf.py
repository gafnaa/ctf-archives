import string

with open("shuffled.bin", "rb") as f:
    data = f.read()

printable = set(bytes(string.printable, 'ascii'))
s = b""
for b in data:
    if b in printable:
        s += bytes([b])
    else:
        if len(s) >= 4:
            print(s)
        s = b""
