data = open('./chall','rb').read()
# offset ditemukan dengan inspeksi (0x2680)
start = 0x2680
obf = data[start:start+46]
res = bytearray(46)
res[0] = 11 ^ 66
for i in range(1,45):
    res[i] = obf[i] ^ 66
print(res[:-1].decode())