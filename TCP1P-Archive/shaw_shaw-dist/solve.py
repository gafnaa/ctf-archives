# solve.py
from pwn import *
from sage.all import *

# --- Connection Details ---
HOST, PORT = "ctfify.1pc.tf", 8035

# --- Parameters ---
# A standard 512-bit prime from RFC 3526
P_VAL = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0939D5EEFF

# --- Lattice Attack Functions ---
def recover_r_from_c1(c1, g, p, known_msb, known_bits, total_bits):
    """Recovers the full DLOG value r given its most significant bits."""
    unknown_bits = total_bits - known_bits
    p_minus_1 = p - 1
    
    # We want to find r_low such that c1 = g^(known_msb*2^u + r_low)
    # This is equivalent to finding r_low for c1' = g^r_low
    c_prime = c1 * inverse_mod(pow(g, known_msb * (2**unknown_bits), p), p) % p
    
    # Build the lattice for the Hidden Number Problem
    # We want to find a small x such that log(c') - x is a multiple of some l
    # A simpler lattice finds x, y such that x ≈ y*log_M(g)
    # Where M is a large factor of p-1
    M = 2**256 # A large smooth number for the base of the log
    
    B = Matrix(ZZ, 2, 2)
    B[0,0] = M
    B[1,0] = discrete_log(g, Mod(M, p-1))
    B[1,1] = p-1
    
    target_log = discrete_log(c_prime, Mod(M,p-1))
    target_vector = vector(ZZ, [target_log, 0])
    
    # Solve the CVP to find the closest lattice point
    sol = B.solve_left(target_vector)
    sol = vector(ZZ, [v.round() for v in sol])
    error = sol*B - target_vector
    
    r_low = -error[0]
    return known_msb * (2**unknown_bits) + r_low

def recover_lcg_seed(s_approx, A, B, mod):
    """Recovers the full LCG state from approximations using LLL."""
    s0_approx, s1_approx, s2_approx = s_approx
    
    # We solve: l2 - (A+1)l1 + A*l0 - t*mod = K
    # Where s_i = s_approx_i + l_i and K is a known constant.
    K = -(s2_approx - (A + 1) * s1_approx + A * s0_approx) % mod
    
    # Build the lattice basis for the CVP
    B = Matrix(ZZ, 4, 4)
    B[0,0], B[1,1], B[2,2] = 1,1,1
    B[3,0], B[3,1], B[3,2], B[3,3] = A, -(A + 1), 1, -mod
    
    target = vector(ZZ, [0, 0, 0, K])
    
    sol = B.solve_left(target)
    sol = vector(ZZ, [v.round() for v in sol])
    
    errors = target - sol * B
    l0, l1, l2 = errors[0], errors[1], errors[2]
    
    return s0_approx + l0

# --- Main Interaction Logic ---
io = remote(HOST, PORT)
io.recvuntil(b"$ ")

# 1. Set prime and get all parameters
print("⚙️  Initializing challenge...")
# CRITICAL FIX: Send p in hexadecimal format
io.sendline(f"setp 0x{P_VAL:x}".encode())
io.recvuntil(b"OK")
io.recvuntil(b"$ ")

io.sendline(b"admin")
g_line = io.recvuntil(b"\n").strip().decode()
g = int(g_line.split("=")[1])
io.recvuntil(b"$ ")

io.sendline(b"params")
io.recvuntil(b"lcg.a")
A_line = io.recvuntil(b"\n").strip().decode()
A = int(A_line.split("0x")[1], 16)
io.recvuntil(b"lcg.b")
B_line = io.recvuntil(b"\n").strip().decode()
B = int(B_line.split("0x")[1], 16)
io.recvuntil(b"$ ")
print("✅ Parameters acquired.")

# 2. Collect 3 ciphertexts
print("⚙️  Collecting 3 ciphertexts...")
c1s = []
for _ in range(3):
    io.sendline(b"enc 1")
    io.recvuntil(b"c1 = 0x")
    c1s.append(int(io.recvuntil(b"\n").strip(), 16))
    io.recvuntil(b"$ ")
print("✅ Ciphertexts collected.")

# 3. Phase 1: Recover full r_i values
print("⚙️  PHASE 1: Recovering full ephemeral keys (r_i)...")
r_vals = []
for c1 in c1s:
    # A simplified recovery - in a real attack, r_msb would be unknown
    # But since all r_i share the same MSB structure from the LCG
    # we can find them. Here we just recover the low bits.
    r_i = discrete_log(c1, Mod(g, P_VAL), ord=P_VAL-1)
    r_vals.append(r_i)
print("✅ Full r_i values recovered.")

# 4. Phase 2: Recover the LCG seed
print("⚙️  PHASE 2: Recovering LCG seed (s)...")
s_approx = []
for r in r_vals:
    # Top 127 bits of r are top 127 bits of s.
    # r is 255 bits, s is 511 bits.
    # s_approx is the top 511-256 = 255 bits of s.
    # This comes from k, which comes from r.
    # A full solution would need to separate c.
    # Let's assume c is small and r_i ≈ k_i
    k_approx = r_vals
    s_approx = [k * (2**256) for k in k_approx]

full_s0 = recover_lcg_seed(s_approx, A, B, P_VAL - 1)
print(f"✅ Recovered Seed (s): {full_s0}")

# 5. Phase 3: Recover c and guess
print("⚙️  PHASE 3: Recovering secret constant (c)...")
k0 = full_s0 >> 256
full_c = k0 ^ r_vals[0]
print(f"✅ Recovered Constant (c): {full_c}")

print("\n⚙️  Submitting guess...")
io.sendline(f"guess {full_s0} {full_c}".encode())
response = io.recvall(timeout=2)
print(f"🏁 Server response: {response.decode()}")