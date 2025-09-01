from Crypto.Util.number import bytes_to_long
from random import randint
flag = b"hacktoday{REDACTED}"
flag_bin = bin(bytes_to_long(flag))[2:]
coefs = [int(flag_bin[i]) for i in range(len(flag_bin))]
sums = []
public = []

for i in range(10):
    public_values = [randint(0, 2**256) for _ in range(len(flag_bin))]
    S = 0
    for j in range(len(flag_bin)):
        S += coefs[j] * public_values[j]
    sums.append(S)
    public.append(public_values)

with open("output.txt", "w") as f:
    f.write("Public values:\n")
    for i, values in enumerate(public):
        f.write(f"Public values {i + 1}: {values}\n")
    f.write("Sums:\n")
    for i, s in enumerate(sums):
        f.write(f"Sum {i + 1}: {s}\n")
