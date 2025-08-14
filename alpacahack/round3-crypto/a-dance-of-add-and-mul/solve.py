from pwn import *

cs = eval(read("a-dance-of-add-and-mul/chall.txt").decode())

p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
E = EllipticCurve(K, (0, 4))
cs = [E(x, y) for x, y in cs]

G1, G2 = E.gens()
o1, o2 = G1.order(), G2.order()

r = 0x5f19672fdf76ce50d28e776116d47d5841f8c5f1fba8d33881bfa40089fc5bffd1ffffff00010001
A1 = [c.weil_pairing(G1, r) for c in cs]
A2 = [c.weil_pairing(G2, r) for c in cs]

v = 0
vs = []
for i in range(len(A1) - 1):
    vs.append(v)
    if A1[i] == A1[i+1] or A2[i] == A2[i+1]:
        v = 1 - v
vs.append(v)
print(unbits(vs))