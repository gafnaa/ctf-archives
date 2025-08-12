from sympy.ntheory import sqrt_mod
from math import ceil, sqrt

# Curve parameters from your script output
p = 1115592147374241288843353323343542263984536204510236592398223661333918863116613813363399441113111039474493948139091241334493
a = 663100293850108605729738073153758766109108192360094245884316724211350332179311535272440004791728249248854436351616646213296
b = 1104349834618511707219749820739045849335328870234054649834822713293879528952741272940688030428611697517823343159031293912558

# Generator x-coordinate
x_g = 690124903672917937877110701762103010581507181155267998801874208752293794283309053502088140839687690486852563648291002229631

# Given x-coordinates from challenge
xs = [
    107272975926831189203093841707559392284196422250425726891770885243136820682014934349433103191527393137164120193928212669026,
    374853083552152078419039464177707506579660105110608120559550314246363586610150004443884038673260767177223398181301219615660,
    485187492909966794004047116680521452300686108500430520950311238302343572058359657075519835637615364779137174912626312338531,
    38193999044104893849164286500179192460028939644654475814230534259565547127270090699694745094032686205767820545022456112085,
    37970831378415192374658635191846065163949293847357070503833815835056062797434179456540474589182901189022239670294761461662,
    139309949922716953726279444353122274003603470688142353561327558900253510008441406378689256197462527465935603671888192962403,
    551768143431797199419974031385844691632760459295442605629449590496465968671785864315071782273280637880717656759522827359850
]

# Elliptic curve over F_p
class ECPoint:
    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.curve == other.curve
    def __neg__(self):
        return ECPoint(self.x, (-self.y) % self.curve.p, self.curve)
    def __add__(self, Q):
        if self.x is None: return Q
        if Q.x is None: return self
        p = self.curve.p
        if self.x == Q.x and (self.y != Q.y or self.y == 0):
            return ECPoint(None, None, self.curve)
        if self.x == Q.x:
            lam = (3*self.x*self.x + self.curve.a) * pow(2*self.y, -1, p) % p
        else:
            lam = (Q.y - self.y) * pow(Q.x - self.x, -1, p) % p
        xr = (lam*lam - self.x - Q.x) % p
        yr = (lam*(self.x - xr) - self.y) % p
        return ECPoint(xr, yr, self.curve)
    def __rmul__(self, n):
        R = ECPoint(None, None, self.curve)  # infinity
        Q = self
        while n:
            if n & 1:
                R = R + Q
            Q = Q + Q
            n >>= 1
        return R

class EllipticCurve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

# Instantiate curve
curve = EllipticCurve(a, b, p)

# Recover generator point (two possible y's, pick one)
y_candidates = sqrt_mod((x_g**3 + a*x_g + b) % p, p, all_roots=True)
G = ECPoint(x_g, y_candidates[0], curve)

# Recover P (dG) from x1 (again pick one possible y)
yP_candidates = sqrt_mod((xs[0]**3 + a*xs[0] + b) % p, p, all_roots=True)
P = ECPoint(xs[0], yP_candidates[0], curve)

# Baby-step giant-step to find d
def bsgs(G, P, order):
    m = ceil(sqrt(order))
    table = {}
    baby = ECPoint(None, None, G.curve)
    for j in range(m):
        table[baby.x, baby.y] = j
        baby = baby + G
    invGm = (-m % order) * G  # Actually incorrect: need scalar mult
    invGm = (-m) * G
    giant = P
    for i in range(m):
        if (giant.x, giant.y) in table:
            return i*m + table[(giant.x, giant.y)]
        giant = giant + invGm
    return None

# Approximate order (just use p for bound)
d = bsgs(G, P, p)
print("[*] Found d =", d)

# Flag
flag_val = a + b + p
flag = b"hacktoday{" + hex(flag_val).encode() + b"}"
print(flag.decode())
