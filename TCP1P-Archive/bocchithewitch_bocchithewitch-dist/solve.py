from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import gmpy2

# Connect to the server
# conn = remote('localhost', 1337)
conn = remote('ctfify.1pc.tf', 8058)

# Standard public exponent
e = 65537
KEY_LEN = 2048
HINT_LEN = 300

# Create a mask to request the 300 Most Significant Bits (MSBs)
mask = ((1 << HINT_LEN) - 1) << (KEY_LEN - HINT_LEN)

log.info(f"Sending mask: {mask}")
conn.sendlineafter(b'mask?> ', str(mask).encode())

# Receive N and the hint
conn.recvuntil(b'N: ')
N = int(conn.recvline().strip())
conn.recvuntil(b'Hint: ')
hint = int(conn.recvline().strip())

# Receive the first ciphertext (ct_0) which encrypts 's'
conn.recvuntil(b'ct_0: ')
ct0_hex = conn.recvline().strip().decode()
ct0 = bytes.fromhex(ct0_hex)

log.info(f"N = {N}")
log.info(f"hint = {hint}")
log.info(f"ct_0 = {ct0.hex()}")

phi = 0
# Iterate through possible values of k
# In CTFs, k is often a small integer, so we don't need to go up to e
for k in range(1, 200000000):
    if k % 100 == 0:
        log.info(f"Trying k = {k}...")
    
    # Calculate our approximation of the multiple of phi(N)
    multiple_approx = e**2 * hint - (e + k)
    
    # Guess C = k*m. Since phi(N) is close to N, C should be close to multiple_approx / N
    # We use integer division with rounding
    C_guess = (multiple_approx + N // 2) // N
    
    if C_guess == 0:
        continue
        
    # Now, calculate a candidate for phi(N)
    # Using the approximation multiple_approx ≈ C * phi
    phi_cand = (multiple_approx + C_guess // 2) // C_guess
    
    # Check if this phi_cand allows us to factor N
    # S = p+q = N - phi + 1
    S = N - phi_cand + 1
    
    # We need to solve p^2 - S*p + N = 0
    # The discriminant delta = S^2 - 4N must be a perfect square
    delta = S*S - 4*N
    
    # --- THIS IS THE CORRECTED LINE ---
    if delta > 0 and gmpy2.is_square(delta):
        log.success(f"Found valid phi at k = {k} and C_guess = {C_guess}!")
        phi = phi_cand
        isqrt_delta = gmpy2.isqrt(delta)
        p = (S + isqrt_delta) // 2
        q = (S - isqrt_delta) // 2
        
        # Sanity check
        if p*q == N:
            log.success(f"Successfully factored N!")
            log.info(f"p = {p}")
            log.info(f"q = {q}")
            break
        else:
            log.warning("Factoring check failed, continuing search...")

if phi == 0:
    log.error("Failed to find phi. The value of k might be larger.")
    exit()

# With phi, calculate the private key d
d = pow(e, -1, phi)

# Construct the full private key and decrypt ct_0
key = RSA.construct((N, e, d, p, q))
cipher = PKCS1_OAEP.new(key)
decrypted_msg_bytes = cipher.decrypt(ct0)

# The message is the secret value 's'
s = bytes_to_long(decrypted_msg_bytes)
log.success(f"Recovered s: {s}")

# Send the guess and get the flag
conn.sendlineafter(b'guess?> ', str(s).encode())
flag = conn.recvall()
log.success(f"Flag: {flag.decode()}")