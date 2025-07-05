import jwt
import datetime

# From app.py
SECRET_KEY = "wildlife-2025-fit-challenge-secret"
JWT_ALGORITHM = "HS256"

def generate_admin_token():
    """
    Generates an admin JWT token with 'role: admin' and 'authorized: True'.
    """
    payload = {
        'role': 'admin',
        'authorized': True,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1) # Token expires in 1 hour
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    return token

if __name__ == '__main__':
    admin_token = generate_admin_token()
    print(f"Generated Admin Token: {admin_token}")
    print("\nTo use this token, set it as a cookie named 'admin_token' in your browser.")
    print("Example for browser console:")
    print(f"document.cookie = 'admin_token={admin_token}; path=/;'")
