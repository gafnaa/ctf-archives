import jwt
import datetime

# Secret key
SECRET_KEY = "12341234"

# Header
header = {
    "alg": "HS256",
    "typ": "JWT"
}

# Payload
payload = {
    "role": "ADMIN",
    "iat": 1742178604,
    "exp": 1742182204
}

# Encode JWT
token = jwt.encode(payload, SECRET_KEY, algorithm="HS256", headers=header)

print("Generated JWT Token:", token)
