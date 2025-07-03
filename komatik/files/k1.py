from pwn import *
import random

SRVR = "ctf.asgama.online"
PORT = 10000

def lagrange_interpolate(x, y, point=0):
    """
    Interpolates the polynomial coefficients and evaluates at `point`.
    Returns P(point), where P is the polynomial defined by (x, y) points.
    """
    total = 0
    n = len(x)
    for i in range(n):
        numerator, denominator = 1, 1
        for j in range(n):
            if i == j:
                continue
            numerator *= (point - x[j])
            denominator *= (x[i] - x[j])
        total += y[i] * numerator // denominator
    return total

def main():
    r = remote(SRVR, PORT)
    
    # Get k
    k_line = r.recvline().decode().strip()
    assert k_line.startswith('k = ')
    k = int(k_line.split('=')[1].strip())
    print(f"[+] Got k = {k}")

    # Read (x, y) shares
    shares = []
    for _ in range(k - 1):
        line = r.recvline().decode().strip()
        if line.startswith('(') and line.endswith(')'):
            x, y = map(int, line[1:-1].split(', '))
            shares.append((x, y))
        else:
            print(f"[ERROR] Unexpected line: {line}")
            r.close()
            return
    
    print(f"[+] Collected {len(shares)} shares")
    
    # Extract x and y lists
    x_list, y_list = zip(*shares)
    
    # Recover the password (coeff0) using Lagrange interpolation at x=0
    password = lagrange_interpolate(x_list, y_list) % 1000000
    print(f"[+] Recovered password: {password}")
    
    # Send the password
    r.sendlineafter(b'password: ', str(password).encode())
    
    # Get the flag
    flag = r.recvline().decode().strip()
    print(f"[+] Flag: {flag}")
    r.close()

if __name__ == "__main__":
    main()