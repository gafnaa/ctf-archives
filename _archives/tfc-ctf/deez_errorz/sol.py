

from Crypto.Util.number import long_to_bytes
import ast
import random
import sys
from math import comb

# ---- Parameters from challenge (adjust if different) ----
mod = 0x225fd                      # modulus used in the challenge
e_values = [97491, 14061, 55776]   # possible small errors

# ---- helpers: modular arithmetic and gaussian elimination ----
def modinv(a, p):
    """Modular inverse (returns None if not invertible)."""
    a %= p
    if a == 0:
        return None
    # extended euclid
    def egcd(a, b):
        if b == 0:
            return (1, 0, a)
        x, y, g = egcd(b, a % b)
        return (y, x - (a // b) * y, g)
    x, y, g = egcd(a, p)
    if g != 1:
        return None
    return x % p

def solve_mod(A, b, p):
    """
    Solve A x = b (mod p) using Gauss-Jordan elimination.
    A: list of n lists (n x n)
    b: list length n
    Returns list x length n or None if singular.
    """
    n = len(A)
    # deep copy and convert to ints mod p
    M = [ [int(A[i][j]) % p for j in range(n)] + [int(b[i]) % p] for i in range(n) ]
    row = 0
    for col in range(n):
        # find pivot
        sel = None
        for r in range(row, n):
            if M[r][col] % p != 0:
                sel = r
                break
        if sel is None:
            continue
        # swap
        M[row], M[sel] = M[sel], M[row]
        inv = modinv(M[row][col], p)
        if inv is None:
            return None
        # normalize pivot row
        for c in range(col, n+1):
            M[row][c] = (M[row][c] * inv) % p
        # eliminate others
        for r in range(n):
            if r != row and M[r][col] != 0:
                factor = M[r][col]
                for c in range(col, n+1):
                    M[r][c] = (M[r][c] - factor * M[row][c]) % p
        row += 1
        if row == n:
            break
    # check for inconsistency and extract solution
    # After Gauss-Jordan we should have diagonal 1s for a non-singular matrix
    x = [0]*n
    for i in range(n):
        # find leading 1 in row i
        lead = None
        for j in range(n):
            if M[i][j] == 1:
                lead = j
                break
            elif M[i][j] != 0:
                # singular or not reduced fully -> can't solve uniquely
                return None
        if lead is None:
            # zero row; if RHS nonzero -> no solution
            if M[i][n] % p != 0:
                return None
            # else free variable (shouldn't happen for full-rank square system)
            return None
        x[lead] = M[i][n] % p
    return x

# ---- parsing out.txt ----
def load_out(filename="out.txt"):
    txt = open(filename, "r").read()
    # Expect "A_values = ... ; b_values = ..."
    if ";" in txt:
        left, right = txt.split(";",1)
    else:
        # fallback try to evaluate whole file as dict style
        parts = txt.split("A_values =")
        if len(parts) < 2:
            raise ValueError("cannot parse out.txt")
        left = "A_values =" + parts[1]
        right = ""
    # safe parse: evaluate A_values and b_values by AST
    # find A_values = <expr>
    A_expr = None
    b_expr = None
    for part in txt.split(";"):
        if "A_values" in part:
            A_expr = part.split("=",1)[1].strip()
        if "b_values" in part:
            b_expr = part.split("=",1)[1].strip()
    if A_expr is None or b_expr is None:
        # last resort: try splitting on 'A_values =' and 'b_values ='
        try:
            A_expr = txt.split("A_values =")[1].split(";")[0].strip()
            b_expr = txt.split("b_values =")[1].strip()
        except Exception as e:
            raise ValueError("cannot find A_values or b_values in out.txt: "+str(e))
    A_values = ast.literal_eval(A_expr)
    b_values = ast.literal_eval(b_expr)
    return A_values, b_values

# ---- vector/matrix helpers ----
def mat_vec_mul(A_rows, vec, p):
    return [ sum((int(A_rows[i][j]) * int(vec[j])) for j in range(len(vec))) % p for i in range(len(A_rows)) ]

# ---- main attack logic ----
def attempt_recover(A_values, b_values, p, e_values, max_tries=2000):
    # sizes
    m = len(A_values)   # number of equations (52)
    n = len(A_values[0])  # number of unknowns (44)
    if m < n:
        raise ValueError("not enough equations")
    # convert to lists of ints
    A = [ [int(x) % p for x in row] for row in A_values ]
    b = [ int(x) % p for x in b_values ]
    print(f"Loaded {m} equations with {n} unknowns. modulus={p}, tries={max_tries}")
    # quick deterministic attempt: try all combinations if small (probably huge, so skip)
    # We'll try random subsets of n rows and solve the square system
    tried_sets = set()
    for attempt in range(max_tries):
        # choose n distinct row indices randomly
        idxs = tuple(sorted(random.sample(range(m), n)))
        if idxs in tried_sets:
            continue
        tried_sets.add(idxs)
        A_sub = [ A[i] for i in idxs ]
        b_sub = [ b[i] for i in idxs ]
        # solve A_sub * S = b_sub (mod p)
        S_cand = solve_mod(A_sub, b_sub, p)
        if S_cand is None:
            # singular submatrix or no unique solution
            continue
        # check residuals on full system
        residuals = mat_vec_mul(A, S_cand, p)
        residuals = [ (residuals[i] - b[i]) % p for i in range(m) ]  # actually A*S mod p but we want A*S - b = -e mod p
        # we expect residuals to equal e_values modulo p (note sign)
        # From generation: b = A*S + e  (mod p) -> A*S - b ≡ -e (mod p)
        # So -residuals should be in e_values mod p, but easier: compute t = (b - A*S) % p should equal e
        t = [ (b[i] - sum((A[i][j]*S_cand[j]) for j in range(n))) % p for i in range(m) ]
        # check if each t is in the set of allowed errors
        ok = all( (ti in e_values) for ti in t )
        if ok:
            print(f"Found consistent solution on attempt {attempt+1}")
            return S_cand
        # small optimization: also allow if most match and remaining few mismatches (if noise): you can try to continue,
        # but original challenge uses small fixed e_values so exact check should succeed
    return None

if __name__ == "__main__":
    try:
        A_values, b_values = load_out("out.txt")
    except Exception as e:
        print("Failed to load out.txt:", e)
        sys.exit(1)

    # parameters
    MAX_TRIES = 5000   # increase if not found quickly (tradeoff time)
    S = attempt_recover(A_values, b_values, mod, e_values, max_tries=MAX_TRIES)
    if S is None:
        print("No consistent solution found. Try increasing MAX_TRIES or inspect data.")
        sys.exit(2)

    # reconstruct flag integer: S is list of base-mod digits with S[0] being least significant digit
    flag_int = 0
    for i, si in enumerate(S):
        flag_int += int(si) * (mod ** i)
    try:
        flag_bytes = long_to_bytes(flag_int)
        print("Recovered flag (raw bytes):")
        print(flag_bytes)
        try:
            print("As UTF-8 string:")
            print(flag_bytes.decode())
        except Exception:
            print("(not valid UTF-8)")
    except Exception as e:
        print("Error converting flag int -> bytes:", e)
        print("Flag int (hex):", hex(flag_int))
