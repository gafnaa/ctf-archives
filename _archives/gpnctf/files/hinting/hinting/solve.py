from Crypto.Util.number import long_to_bytes

# Values from output.txt
n_hex = "9a76146efef65dcc5acbf13b388449be3cf45c1618d2b8b57dc5701878c0e98439ec8cc68f31cb91e8fd0840e490c6fc678cefca4f5f705d1a6b627069bad2b9f68f5cb9cdc9829a0431a3739570645cb6607f25eae5d61b93cf79ba326234705d63a381a407756210da1d0ea009efe72e22fd7990388a16b377ce1ff60f40061f0a0fdc449051d97b143c0e5823245449f5c5e60b5b1a542dfb3c7d2455937c098287e9a082fe77bde9add248f6507f030707986d94f600ee6f8051550f114c9923ff09251e19038ef536b52815db98c2c328686e7600e39a4499fba4a916af9bb6d5bc86585c1c65f0f9d85e2634ffcfcaf910da81e08bb4b4a6e64da625815"
e_hex = "10001"
c_hex = "9773a4e4cad0b0439e9de27780a02f4a6eaf6c5f131a82198c0bbca9306b47c2aee4385190b5f29f38fbfa0641dd871c395cd20a931270ca9210947be21dc1ca03c92244e62d34848a6981cead03427db413efd4c1e84615647cc01e21e5aa0f2e35312f8200bf2ffc16149d444c5cf6186a8073b7c26913df2f137edee41a7a0a2356e3100e7b3c741aede3b7e162d38a30029928e8c86e9b9df22f39dfb4ef1b61a3175a3a8127a88a12824e4ecef373fcbcbd421939257d7c253bdbd467b25a444d3ed5b21560d63800a779c046e8082a6067cb555744d3a95d0772fcd1d99aec78183a2e985fa86ba6f14c953256a70247503bb02a2666d27f2bc34516fa"
p_dec = "119837764317547446492869415350972615794016967274631395417526200096585682513220796105318524752481324085624194644142063909462703364043592629244268424590447042618519527359459740804619325015001838508414162211566806549744695745236850366274182026467017190849215377171717241526158831823430686687848105163631752892603"
q_dec = "162711031906852887257827390836084002972804651109810136855735973438383958181095060197120711027071845651892088286014019683697507631865949600424604411382074133994107388093331441247394082391025619962788252080337856196613904486047219863547691733043368151911484830369208589642481163571316972454041609471179478963567"

# Convert hex strings to integers
n = int(n_hex, 16)
e = int(e_hex, 16)
c = int(c_hex, 16)

# Convert decimal strings to integers
p = int(p_dec)
q = int(q_dec)

print(f"p bit length: {p.bit_length()}")
print(f"q bit length: {q.bit_length()}")
print(f"n bit length: {n.bit_length()}")

# Calculate phi
phi = (p - 1) * (q - 1)

# Calculate private exponent d
d = pow(e, -1, phi)

# Decrypt the ciphertext
decrypted_flag_int = pow(c, d, n)

# Convert the decrypted integer to bytes
flag = long_to_bytes(decrypted_flag_int)

print(f"Decrypted flag integer bit length: {decrypted_flag_int.bit_length()}")
print(f"Original decrypted bytes length: {len(flag)}")
print(f"Original decrypted bytes (hex): {flag.hex()}")

# Strip leading null bytes, which can happen with long_to_bytes
flag = flag.lstrip(b'\x00')

print(f"Stripped decrypted bytes length: {len(flag)}")
print(f"Stripped decrypted bytes (hex): {flag.hex()}")

try:
    decoded_flag = flag.decode('ascii')
    print(f"Decoded Flag (ASCII): {decoded_flag}")
except UnicodeDecodeError:
    print("Failed to decode as ASCII. Attempting latin-1.")
    try:
        decoded_flag = flag.decode('latin-1')
        print(f"Decoded Flag (latin-1): {decoded_flag}")
    except UnicodeDecodeError:
        print("Failed to decode as latin-1. Printing raw bytes and hex.")
        print(f"Decrypted Flag (raw bytes): {flag}")
        print(f"Decrypted Flag (hex): {flag.hex()}")
        print("The flag might contain non-printable characters or be in a specific format.")
