from sage.all import GF, EllipticCurve, ZZ

# Set up curve
p = 0xbde3c425157a83cbe69cee172d27e2ef9c1bd754ff052d4e7e6a26074efcea673eab9438dc45e0786c4ea54a89f9079ddb21
E = EllipticCurve(GF(p), [5, 7])

# Find the appropriate multiplication factor
factor_list = E.order().factor(limit=2**10)
m = factor_list  # The 4th factor's base

TARGET_X = 0x686be42f9c3f431296a928c288145a847364bb259c9f5738270d48a7fba035377cc23b27f69d6ae0fad76d745fab25d504d5

def try_flag(flag_base='ictf{', flag_len=10):
    import itertools
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}'
    for guess in itertools.product(charset, repeat=flag_len):
        flag = flag_base + ''.join(guess) + '}'
        x_int = int.from_bytes(flag.encode(), 'big')
        try:
            P = E.lift_x(ZZ(x_int))
            mP = m * P
            if mP.x() == TARGET_X:
                print('Found:', flag)
                break
        except Exception:
            continue  # Sometimes lifting fails if not valid x

# Call try_flag with reasonable flag length
try_flag(flag_base='ictf{', flag_len=10)
