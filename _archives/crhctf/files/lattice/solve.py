from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from sage.all import Matrix, ZZ, inverse_mod, vector
import itertools

# -------------- paste challenge data --------------
Qx = 97807947985096161804355732287982753654948031534592619413324094997123323826739

sigs = [
(50658460383356839460979921779058660085431659138336527004561825291835819056804,
 15850652019778287159181648273271057077857252067295554884511726592433856004955),
(55021558662059447624798058172147092977535149253064191890036638955424342991727,
 74553053530485102972794074692893327695307196166246697328850608864367232027860),
(30479934388831147873799837596662669512786812168070523970113395515778733960560,
 24795513289186384624402347385289431030294290384764332702903267759322698549323),
(105837751039535424559125644715870967168975265675053708037661158119949086718741,
 34322229408348037372747722870510689860223438200463919013767954018481873308042),
(29755510144869154344956611474205380034219221937592878531082778231633908520693,
 90802786861810650502837812803785663278073189428623894144782372853351534201266),
(81476943002290977298605252983624488256852285686939369751236802174273258924703,
 76125563968319436945740791182365902972202388557882652962877204412103358147936),
(28261512207892426224742133858705952910512697868735737188525240842635310379121,
 72524968561911868126689165463494021914038765141242718996701297339646827995055),
(87710736467323984781434451294397381339986854981796616474558454870226909597785,
 8253967440051485588971581354001826947025694400823436258129687301057096956293),
(60226781003242921722706257356256557663467850819801351549557281916623976835902,
 16080056968321866311295326477870779138609421008224138407194499563948854826683),
(72238256033123334662456106980189329192393498098949141696572737611506613581447,
 17507752889992449167413404197668789112266365286127119900030769586272616824807)
]

msgs = [
b"The true sign of intelligence is not knowledge but imagination.",
b"In the middle of difficulty lies opportunity.",
b"I have no special talent. I am only passionately curious.",
b"The only source of knowledge is experience.",
b"Logic will get you from A to B. Imagination will take you everywhere.",
b"Life is like riding a bicycle. To keep your balance, you must keep moving.",
b"Strive not to be a success, but rather to be of value.",
b"Weakness of attitude becomes weakness of character.",
b"Peace cannot be kept by force; it can only be achieved by understanding.",
b"It's not that I'm so smart, it's just that I stay with problems longer."
]

enc_flag = bytes.fromhex("79db35dbbede035ad9587883668089967888c84b7ae9a240374efdd6be77b3c2149b4491fa6b3203665edfededc051286e542f28dab37ebb6a5994ac6390bea77e61fe9c75c47ced53e8d7f43fd5")
nonce = bytes.fromhex("eb1354aa22946d8305f1968f2cf985f6")
tag = bytes.fromhex("5db7cb1bd95658b84adc9e4dbda93d8d")

# SECP256k1 order
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# -------------- preprocess e_i, r_i, s_i --------------
rs = [int(r) for r,s in sigs]
ss = [int(s) for r,s in sigs]
hs_bytes = [sha256(m).digest() for m in msgs]

def compute_e(r, Qx_bytes, h_bytes):
    return int.from_bytes(sha256(r.to_bytes(32,'big') + Qx_bytes + h_bytes).digest(), 'big') % n

Qx_bytes = Qx.to_bytes(32,'big')
es = [ compute_e(r, Qx_bytes, h) for r,h in zip(rs, hs_bytes) ]

m = len(es)
print(f"Using {m} signatures. n = {n}")

# -------------- helper: test candidate d --------------
K_bound = 2**128
def test_d(d):
    # compute kis = (s - e*d) mod n and check bounds
    kis = [ (ss[i] - (es[i]*d) ) % n for i in range(m) ]
    ok = all(k < K_bound for k in kis)
    return ok, kis

# -------------- lattice builders and attempts --------------

def try_basis_variant_1(K, M):
    # (m+1) x (m+1) lattice:
    # rows 0..m-1: diag K, last col = s_i
    # last row: [ e0*M, e1*M, ..., em-1*M, M*n ]
    B = Matrix(ZZ, m+1, m+1)
    B.set_zero()
    for i in range(m):
        B[i,i] = K
        B[i,m] = ss[i]
    for j in range(m):
        B[m,j] = es[j]*M
    B[m,m] = M*n
    return B

def try_basis_variant_2(K, S):
    # (m+2) x (m+2) variant inspired by some writeups
    B = Matrix(ZZ, m+2, m+2)
    B.set_zero()
    for i in range(m):
        B[i,i] = K
    # row m: es entries, last column n
    for j in range(m):
        B[m, j] = es[j]
    B[m, m] = n
    # anchor row with scale S
    B[m+1, m] = S
    B[m+1, m+1] = S * K
    return B

# generate parameter grids to try
K_choices = [2**127, 2**128, 2**129]
M_guess = n // (2**128)
M_choices = [max(1, M_guess//2), M_guess, M_guess*2, 1]
S_choices = [2**180, 2**200, 2**220, 2**230]

attempts = 0
found = []

print("Starting lattice attempts (multiple scalings). This may take a bit...")

for K, M, S in itertools.product(K_choices, M_choices, S_choices):
    # variant 1
    attempts += 1
    try:
        B1 = try_basis_variant_1(K, M)
        L1 = B1.LLL()
        # search for candidate vectors in LLL basis
        for row in L1.rows():
            vec = list(map(int, row))
            kis = vec[0:m]
            # attempt to recover d from any index where e_i invertible
            for i in range(m):
                e_i = es[i]
                if e_i % n == 0:
                    continue
                rhs = (ss[i] - kis[i]) % n
                try:
                    d_candidate = (rhs * inverse_mod(e_i, n)) % n
                except Exception:
                    continue
                ok, kis_check = test_d(d_candidate)
                if ok:
                    print(f"\nFOUND (variant1) K={K}, M={M}, S={S} after {attempts} attempts")
                    print("d =", d_candidate)
                    found.append(('v1', K, M, S, d_candidate, kis_check))
                    # try decrypt
                    key = sha256(d_candidate.to_bytes(32,'big')).digest()[:16]
                    try:
                        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        plain = aes.decrypt_and_verify(enc_flag, tag)
                        print("DECRYPT OK:", plain)
                        raise SystemExit(0)
                    except Exception as e:
                        print("Decryption failed with d (maybe wrong):", e)
    except Exception as e:
        # print("variant1 error", e)
        pass

    # variant 2
    attempts += 1
    try:
        B2 = try_basis_variant_2(K, S)
        L2 = B2.LLL()
        for row in L2.rows():
            vec = list(map(int, row))
            kis = vec[0:m]
            # try extract candidate d same way
            for i in range(m):
                e_i = es[i]
                if e_i % n == 0:
                    continue
                rhs = (ss[i] - kis[i]) % n
                try:
                    d_candidate = (rhs * inverse_mod(e_i, n)) % n
                except Exception:
                    continue
                ok, kis_check = test_d(d_candidate)
                if ok:
                    print(f"\nFOUND (variant2) K={K}, M={M}, S={S} after {attempts} attempts")
                    print("d =", d_candidate)
                    found.append(('v2', K, M, S, d_candidate, kis_check))
                    # try decrypt
                    key = sha256(d_candidate.to_bytes(32,'big')).digest()[:16]
                    try:
                        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
                        plain = aes.decrypt_and_verify(enc_flag, tag)
                        print("DECRYPT OK:", plain)
                        raise SystemExit(0)
                    except Exception as e:
                        print("Decryption failed with d (maybe wrong):", e)
    except Exception as e:
        # print("variant2 error", e)
        pass

print("Attempts finished. Results:")
if found:
    for item in found:
        print(item)
else:
    print("No candidate d found with tried parameter grid.")
    print("Next suggestions:")
    print("- Try increasing the number of signatures (if you can re-run challenge to produce more).")
    print("- Try larger S scaling (e.g. 2**260) or K choices around 2**126..2**130.")
    print("- Try BKZ (if available) or run LLL multiple times with randomized small perturbations.")
    print("- If you want, paste full LLL basis output and I'll tune further.")