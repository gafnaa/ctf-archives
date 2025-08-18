# This script must be run in a SageMath environment (e.g., `sage -python decryptor.py`)
# It requires the following Python libraries: pycryptodome, ecdsa
# You can install them via pip:
# sage -pip install pycryptodome ecdsa

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from ecdsa.curves import SECP256k1
from hashlib import sha256
from sage.all import Matrix, ZZ, vector

def decrypt():
    """
    Recovers the private key by exploiting small nonces in the signature scheme
    and then decrypts the flag.
    """
    # --- Provided Data from out.txt ---
    Q_x = 97807947985096161804355732287982753654948031534592619413324094997123323826739
    Q_y = 67741340960897337662050584132725854587173198377001983557101362922093290658991
    
    # Signatures (r, s)
    sigs = [
        (50658460383356839460979921779058660085431659138336527004561825291835819056804, 15850652019778287159181648273271057077857252067295554884511726592433856004955),
        (55021558662059447624798058172147092977535149253064191890036638955424342991727, 74553053530485102972794074692893327695307196166246697328850608864367232027860),
        (30479934388831147873799837596662669512786812168070523970113395515778733960560, 24795513289186384624402347385289431030294290384764332702903267759322698549323),
        (105837751039535424559125644715870967168975265675053708037661158119949086718741, 34322229408348037372747722870510689860223438200463919013767954018481873308042),
        (29755510144869154344956611474205380034219221937592878531082778231633908520693, 90802786861810650502837812803785663278073189428623894144782372853351534201266),
        (81476943002290977298605252983624488256852285686939369751236802174273258924703, 76125563968319436945740791182365902972202388557882652962877204412103358147936),
        (28261512207892426224742133858705952910512697868735737188525240842635310379121, 72524968561911868126689165463494021914038765141242718996701297339646827995055),
        (87710736467323984781434451294397381339986854981796616474558454870226909597785, 82539674400514855889715813540018269470256944008234362582561057096987377956293),
        (60226781003242921722706257356256557663467850819801351549557281916623976835902, 16080056968321866311295326477870779138609421008224138407194499563948854826683),
        (72238256033123334662456106980189329192393498098949141696572737611506613581447, 17507752889992449167413404197668789112266365286127119900030769586272616824807)
    ]
    
    # Encrypted flag data
    enc_flag = bytes.fromhex("79db35dbbede035ad9587883668089967888c84b7ae9a240374efdd6be77b3c2149b4491fa6b3203665edfededc051286e542f28dab37ebb6a5994ac6390bea77e61fe9c75c47ced53e8d7f43fd5")
    nonce = bytes.fromhex("eb1354aa22946d8305f1968f2cf985f6")
    tag = bytes.fromhex("5db7cb1bd95658b84adc9e4dbda93d8d")

    # --- Elliptic Curve and Message Data ---
    C = SECP256k1
    n = C.order
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

    # --- Attack Logic ---

    # 1. Calculate e_i for each signature
    # e = H(r || Q.x || H(m))
    print("Step 1: Calculating hash values (e_i) for each signature...")
    e_values = []
    s_values = []
    for i, (r, s) in enumerate(sigs):
        s_values.append(s)
        msg_hash = sha256(msgs[i]).digest()
        # Ensure r and Q.x are 32 bytes for concatenation
        r_bytes = long_to_bytes(r, 32)
        Qx_bytes = long_to_bytes(Q_x, 32)
        
        combined_hash = sha256(r_bytes + Qx_bytes + msg_hash).digest()
        e = int.from_bytes(combined_hash, 'big') % n
        e_values.append(e)
    print("Done.")

    # 2. Set up the lattice for the Hidden Number Problem (HNP)
    # The vulnerability is that k_i = (s_i - e_i*d) mod n is small (< 2^128).
    # We can solve for d by finding a vector close to a target vector in a lattice.
    print("\nStep 2: Setting up the lattice...")
    m = len(sigs)
    # Scaling factor to balance the components of the target vector
    M = 2**128 

    # Create the basis matrix B
    B = Matrix(ZZ, m + 1, m + 1)
    
    # Set diagonal elements for the modulo n part
    for i in range(m):
        B[i, i] = M * n

    # Set the last row with the e_i values and the final scaling component
    for i in range(m):
        B[m, i] = M * e_values[i]
    B[m, m] = 1 # This corresponds to the unknown private key d
    print("Lattice basis created.")

    # Create the target vector T
    T = vector(ZZ, [M * s for s in s_values] + [0])

    # 3. Reduce the lattice basis using LLL
    print("\nStep 3: Running LLL algorithm to find a reduced basis...")
    B_red = B.LLL()
    print("LLL reduction complete.")

    # 4. Solve the Closest Vector Problem (CVP) using Babai's rounding method
    print("\nStep 4: Solving the Closest Vector Problem (CVP)...")
    # **FIX**: Implement Babai's rounding algorithm to avoid Lattice import issues.
    # We want to find an integer vector c such that c * B_red is close to T.
    # We can approximate c by T * B_red^(-1) and then rounding the components to integers.
    try:
        B_red_inv = B_red.inverse()
        c = T * B_red_inv
        # Round components to nearest integers and create an integer vector
        c_rounded = vector(ZZ, [round(ci) for ci in c])
        L_close = c_rounded * B_red
    except Exception as e:
        print(f"An error occurred during CVP solving: {e}")
        print("The lattice basis might be singular. Attack failed.")
        return
    
    # The solution vector V contains information about k_i and d
    V = T - L_close

    # 5. Extract and verify the private key d
    print("\nStep 5: Extracting and verifying the private key...")
    # The last element of our solution vector V should be -d
    d = -V[m]

    if d < 0:
        d = d % n # Ensure d is in the correct range

    # Verify that this d produces small nonces k_i for all signatures
    is_valid = True
    for i in range(m):
        k = (s_values[i] - e_values[i] * d) % n
        if not (0 < k < M):
            print(f"Verification FAILED for signature {i}. Nonce k is out of expected range.")
            is_valid = False
            break
    
    if is_valid:
        print(f"Verification SUCCESSFUL!")
        print(f"Found private key d: {d}")

        # 6. Decrypt the flag
        print("\nStep 6: Decrypting the flag...")
        key = sha256(long_to_bytes(d, 32)).digest()[:16]
        aes = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            flag = aes.decrypt_and_verify(enc_flag, tag)
            print("\n" + "="*40)
            print(f"  DECRYPTED FLAG: {flag.decode()}")
            print("="*40)
        except ValueError as e:
            print(f"Decryption failed: {e}. The key is likely incorrect.")
    else:
        print("\nCould not find the correct private key. The attack failed.")

if __name__ == "__main__":
    decrypt()
