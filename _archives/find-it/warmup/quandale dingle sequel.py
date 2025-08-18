from Cryptodome.Util.number import long_to_bytes, bytes_to_long
import math

n = input n dari output server
e = input e dari output server
ct1 = input ct1 dari output server
ct2 = input ct2 dari output server

evolutions = [b'alpha', b'sigma', b'ligma', b'omega', b'skibi', b'rizlr']
all_diffs = [ bytes_to_long(a) - bytes_to_long(b) for b in evolutions for a in evolutions if a != b]


# adapted from https://github.com/yud121212/Coppersmith-s-Short-Pad-Attack-Franklin-Reiter-Related-Message-Attack/blob/master/coppersmiths_short_pad_attack.sage
def short_pad_attack(i, known_diff):
    PRxy.<x,y> = PolynomialRing(Zmod(n))
    PRx.<xn> = PolynomialRing(Zmod(n))
    PRZZ.<xz,yz> = PolynomialRing(Zmod(n))

    g1 = x^e - ct1
    g2 = (x+y+2^i * known_diff)^e - ct2

    q1 = g1.change_ring(PRZZ)
    q2 = g2.change_ring(PRZZ)


    h = q2.resultant(q1)
    h = h.univariate_polynomial()
    h = h.change_ring(PRx).subs(y=xn)
    h = h.monic()

    kbits = n.nbits()//(2*e*e)
    roots = h.small_roots(X=2^kbits, beta=0.5) 

    if roots == []:
        return -1
    else:
        return roots[0]

def fr(diff):
    R.<X> = Zmod(n)[]
    f1 = X^e - ct1
    f2 = (X + diff)^e - ct2
    g = polygcd(f1,f2).coefficients()[0]
    if g > 1:
        print(long_to_bytes(int(n-g)))


def polygcd(a, b):
    if(b == 0):
        return a.monic()
    else:
        return polygcd(b, a % b)

for i in range(8*30, 200*8, 8):
    print(i)
    for known_diff in all_diffs:
        diff = short_pad_attack(i, known_diff)
        if (diff != -1):
            print("found diff")
            fr(diff + 2^i * known_diff)
