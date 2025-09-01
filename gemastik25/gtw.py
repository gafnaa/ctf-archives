# SAGE SCRIPT - RUN WITH: sage gtw.py

from pwn import remote, process, log as pwnlog
from sage.all import *

def solve_s(N, c, f, U1):
    """
    Final, correct implementation using Hensel's Lemma.
    All calculations are strictly handled within Sage's IntegerModRing
    to ensure mathematical and type correctness.
    """
    # Define the mathematical "rings" for our calculations
    Z_N = IntegerModRing(N)
    Z_N2 = IntegerModRing(N**2)

    # Cast initial Python integers into Sage's integer type for safety
    s_e_int = Integer(U1 % N)
    e_M1_int = Integer(f - c)
    U1_int = Integer(U1)
    
    # --- All calculations below use Sage objects ---
    
    # 1. Calculate the inverse of s_e in the Z_N ring
    inv_s_e_N = Z_N(s_e_int)**-1

    # 2. Lift the inverse from modulo N to modulo N^2. This is the core of the method.
    inv_s_e_N2 = Z_N2(inv_s_e_N) * (2 - Z_N2(s_e_int) * Z_N2(inv_s_e_N))

    # 3. Calculate V = U1 * (s_e)^-1 (mod N^2). This must be done in the Z_N2 ring.
    V = Z_N2(U1_int) * inv_s_e_N2

    # 4. Extract the coefficient 'k' from the resulting expression V = (1 + k*N)
    L_V = (V.lift() - 1) // N

    # 5. Solve for the inverse of s: s_inv = k * (e*M1)^-1 (mod N)
    s_inv = Z_N(L_V) * (Z_N(e_M1_int)**-1)

    # 6. Invert the result to find the final secret, s
    s = s_inv**-1

    # Convert the final Sage object back to a standard Python integer for sending
    return int(s.lift())

# --- Main Connection and Interaction Logic ---
conn = remote("20.6.89.33", 8055)

for i in range(1, 13):
    pwnlog.info(f"Solving Round {i}/12...")
    
    try:
        conn.recvuntil(f"=== Round {i}/12 ===\n".encode())
        N = int(conn.recvline().strip().split(b" = ")[1])
        conn.recvline()
        c = int(conn.recvline().strip().split(b" = ")[1])
        f = int(conn.recvline().strip().split(b" = ")[1])
        conn.recvline()
        U1 = int(conn.recvline().strip().split(b" = ")[1])
        conn.recvline()
        
        s_guess = solve_s(N, c, f, U1)
        pwnlog.success(f"Calculated s = {s_guess}")
        
        conn.sendlineafter(f"Enter guess for round {i}/12 >> ".encode(), str(s_guess).encode())
        
        response = conn.recvline().decode().strip()
        pwnlog.info(f"Server: {response}")
        if "Fail!" in response:
            pwnlog.failure("Failed round. Exiting.")
            break
    except EOFError:
        pwnlog.failure("Connection closed unexpectedly.")
        break

if "Fail!" not in response:
    pwnlog.success("All rounds passed! Receiving flag...")
    flag = conn.recvall(timeout=2).decode()
    print(f"\n[+] FLAG: {flag.strip()}\n")

conn.close()