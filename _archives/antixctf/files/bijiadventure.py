# Import the necessary function to convert the decrypted number back to bytes.
from Crypto.Util.number import long_to_bytes, inverse

# These are the values you provided from the encryption script.
n = 9229758949951551058954763105712663610511238574094785753136243883301687808233118345426024686323946672142096482730675100953776621497685108185003935641409953
c = 5658357805960315334456435100794068418572874937349161652544362994830137186868263670673899072400617463788634874854423048741757250885067819996144252700834217

# The public exponent 'e' is a standard value.
e = 0x10001

# --- The Vulnerability ---
# In standard RSA, n = p * q, and phi = (p-1) * (q-1).
# However, in this case, 'n' is a prime number.
# The totient of a prime number 'n' is simply n - 1.
# This makes it trivial to find the private key.
phi = n - 1

# --- The Solution ---
# Calculate the private key 'd', which is the modular multiplicative inverse
# of 'e' with respect to phi.
# d * e ≡ 1 (mod phi)
d = inverse(e, phi)

# Decrypt the ciphertext 'c' by raising it to the power of 'd' modulo 'n'.
# m = c^d mod n
decrypted_message_long = pow(c, d, n)

# Convert the resulting long integer back into bytes to reveal the flag.
flag = long_to_bytes(decrypted_message_long)

# Print the final flag.
print(f"Decrypted flag: {flag.decode()}")
