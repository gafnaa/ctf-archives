# solve.py
from Crypto.Util.strxor import strxor
from hashlib import sha3_512, sha256
from sage.all import *

# --- Provided values ---
out = [3254198153523356424296236228714324648103429186631123569886474302400042287749973715766509950478153391942181649055522947047235765718568514132285930194671940122451253316578763308554079885826612258065807194978581247866624390381760917438019072999506458451624810474576035309040890443050164325315, 325419815352335642429623622871432464810342918663112356988647430240004228775109013430554900489587558397050167548146019261270195036491400902197516853439888588574268020679873561174785064735736546589852820080669901199777422243183773720967271968233318505234678904844401732299701659679283061519, 3254198153523356424296236228714324648103429186631123569886474302400042287750292099194334172097180268192508720722423931490198518461777017038233606494828398006950715203148482411949563050405110282383134406288387609573016435783748810295221763833124332541899576708912616845145007685560722582498, 3254198153523356424296236228714324648103429186631123569886474302400042287752913339618704129723681111372142381023828483439151259060395723449389198535149257859182213461125672317371428817182927615917907818229114396875620786828015066909115176234851284031804987715619966551446656967907098330495, 3254198153523356424296236228714324648103429186631123569886474302400042287752396314226169203412224217354585989105299935222989234137967132948622204346485979553088033967486702515642016049794819515466859106951981712587777961448927026890545759484527701823953890201122468721022989998303511158297, 3254198153523356424296236228714324648103429186631123569886474302400042287752919598842703608373867277152313264126397444426523411443656661437893628823611952937998458992460770778991897192784321003531555915492391488256929405160807875493169536660547714774613057353827831697432561496711588370883, 3254198153523356424296236228714324648103429186631123569886474302400042287742579928161837351468099707628692009460224141045928174776693595394890770178847113925779969416442545304112745060775075125740948157432337406635853172171106943876511135296041104376378567071633424170961567513722779756524]
# Corrected the typo \dd to \xdd
ct = b'\x8e\x03\xfd\xf1\xe1\xa5\xaa>a\x88\xfc\xe0p7\xec\xb1\xb9\xddP{\xcdV\xb1\x05T3n\xfd#\xcb,\xfbQ\xaa\x1fm\xea\x87+\xcf\xf2\xfd\xa9rA'
hint = "87bc8da067d16d4323b9055daa79201018add7fa5b9866be3dd41450641b5de2"

P = 19909
O = [val * (2**64) for val in out]
C = [(O[i] - O[i+1]) // P for i in range(len(O)-1)]

def solve():
    ## Step 1: Use LLL to find the differences d[i]
    print("⚙️  Building the correct lattice and running LLL...")
    
    # This is the standard construction for finding a vector of small integers
    # [d1, d2, d3, d4, d5, d0] that satisfies d_i/d_0 ≈ C_i/C_0
    B = Matrix(ZZ, 6, 6)
    N = 2**250 # Weight chosen to match the expected size of the d_i
    
    # Top-left 5x5 is the identity matrix
    for i in range(5):
        B[i, i] = 1
        
    # Last row contains the scaled relations
    last_row = [-Integer(round(N*C[i+1]/C[0])) for i in range(5)] + [N]
    B[5,:] = vector(ZZ, last_row)
    
    B_LLL = B.LLL()
    
    # The shortest vector gives us the coefficients we need to reconstruct d
    # v = [x0, x1, x2, x3, x4, x5]
    # d_{i+1} = -v_i for i=0..4, and d_0 = v_5
    v = B_LLL[0]
    d_diffs = [v[5]] + [-v[i] for i in range(5)]
    
    # Ensure the sign of d[0] matches C[0] so their ratio r is positive.
    if (d_diffs[0] > 0) != (C[0] > 0):
        d_diffs = [-x for x in d_diffs]

    print("✅ Found candidate for difference vector d.")

    ## Step 2: Find r
    if d_diffs[0] == 0:
        raise ValueError("LLL resulted in a zero vector, cannot proceed.")
    
    numerator = sum(C[i] * d_diffs[i] for i in range(6))
    denominator = sum(d_diffs[i]**2 for i in range(6))
    r_cand = numerator // denominator
    r = 0
    print(f"⚙️  Searching for r around candidate...")

    for offset in range(-20000, 20000):
        r_test = r_cand + offset
        if sha256(f"{r_test}".encode()).hexdigest() == hint:
            r = r_test
            print(f"✅ Found r: {r}")
            break
    
    if r == 0:
        raise ValueError("Failed to find r. The core approximation may be flawed.")

    ## Step 3: Find x_0 using binary search
    print("⚙️  Searching for x0 via binary search...")
    S = [0] * 7
    for j in range(6):
        S[j+1] = S[j] + d_diffs[j]

    def get_k_val(x0):
        g0 = (x0 + S[0]) * P
        k_val = O[0] - r * (g0 ^ r)
        return k_val

    low = 0
    high = 2**249
    x0 = 0

    while low <= high:
        mid = (low + high) // 2
        if mid == 0: low = 1; continue
        k_val = get_k_val(mid)
        
        if k_val < 0 or k_val.bit_length() > 512:
            low = mid + 1
        else:
            high = mid - 1

    x0 = low
    k_final = get_k_val(x0)
    
    if not (0 < k_final < 2**512):
        raise ValueError("Binary search for x0 failed to find a valid k.")

    print(f"✅ Found x0: {x0}")
    print(f"✅ Calculated k has bit length: {k_final.bit_length()}")

    ## Step 4: Decrypt the flag
    gs = [(x0 + s) * P for s in S]
    key_material = f"{gs};{[r]}".encode()
    key = sha3_512(key_material).digest()[:len(ct)]
    flag = strxor(ct, key)

    print("\n🎉 Decryption Complete!")
    print(f"🚩 Flag: {flag.decode()}")

solve()