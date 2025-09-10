
import json
import socket
import sys
import hashlib
from decimal import Decimal, getcontext
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

HOST = "leaky-rsa.chal.imaginaryctf.org"
PORT = 1337

# Helper to recv one JSON line
def recv_json(f):
    line = f.readline()
    if not line:
        raise EOFError("Connection closed")
    return json.loads(line.strip())

# Send our ciphertext integer as JSON {"c": int}
def send_c(f, c):
    f.write((json.dumps({"c": int(c)}) + "\n").encode())
    f.flush()

# Compute AES-CBC decrypt
def aes_decrypt_from_key_m(key_m, iv_hex, ct_hex):
    key = hashlib.sha256(str(int(key_m)).encode()).digest()[:16]
    iv = bytes.fromhex(iv_hex)
    ct = bytes.fromhex(ct_hex)
    pt = unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct), 16)
    return pt

# Attack using generalized LSB oracle via multiplicative blinding
# We maintain an interval [low, high) that contains m, progressively halving it.
# We query m' = m * 2^t mod n and read b = bit_k(m'), for varying (t,k).
# With k=0 (parity), we get classic Bleichenbacher LSB narrowing: if m*2 mod n wraps over n, parity flips distribution.
# Here we adapt a robust scheme that mostly uses k=0 parity because it leads to clean interval halving;
# extra bits (k=1..3) are used for tie-breaks when parity decisions are ambiguous.
def recover_m(f, n, key_c, e=65537):
    # precision for Decimal arithmetic
    kbits = n.bit_length()
    getcontext().prec = kbits + 10
    low = Decimal(0)
    high = Decimal(n)

    # Precompute 2^e mod n for streaming multiplications
    two_e = pow(2, e, n)

    # Current ciphertext we'll keep multiplying by 2^e each parity step
    c_cur = key_c

    # Ensure we never send exactly key_c (oracle forbids equality)
    # Start by multiplying once by 2^e so c_cur != key_c
    c_cur = (c_cur * two_e) % n

    # Run up to kbits + a safety margin of iterations
    # Each parity query halves interval on average
    for i in range(kbits + 5):
        # Read oracle prompt: {"idx": idx}
        prompt = recv_json(f)
        assert "idx" in prompt
        idx = prompt["idx"]

        # Strategy: prefer idx==0 (parity) steps; if server asks a nonzero idx,
        # we still send c_cur and accept the bit, but we only update interval on parity steps.
        # To increase chance of parity steps, we don't control idx, but we can hold c_cur steady until a parity step appears.
        send_c(f, c_cur)
        resp = recv_json(f)
        b = resp.get("b", 2)
        if b == 2:
            # If malformed, advance c_cur to keep desync minimal
            c_cur = (c_cur * two_e) % n
            continue

        # When idx==0, apply classic LSB-oracle update:
        # After multiplying ciphertext by 2, plaintext effectively doubles modulo n.
        # Interpretation: m is uniformly in [low, high).
        # Doubling map: if 2*low >= n or 2*high > n, wrapping splits mass.
        mid = (low + high) / 2

        if idx == 0:
            # For parity oracle: b == LSB(m*2 mod n)
            # Standard narrowing rule:
            # If b == 0 -> m*2 mod n is even => m in lower half
            # If b == 1 -> m in upper half
            # This corresponds to:
            #   if b==0: high = mid
            #   else: low = mid
            if b == 0:
                high = mid
            elif b == 1:
                low = mid
            # Move to next doubled ciphertext
            c_cur = (c_cur * two_e) % n
        else:
            # For idx in {1,2,3}, we don't have a simple, guaranteed halving rule.
            # Use them as occasional refinements:
            # Heuristic: aggregate a few same-(t,k) observations is tricky without control of t.
            # We'll skip interval update here; still advance c_cur to avoid equality on next send.
            c_cur = (c_cur * two_e) % n

        # Optional early stop when interval small enough
        if (high - low) < 1:
            break

    # Final estimate: take ceil(low)
    m_est = int(high)
    # Clamp into [0, n-1]
    m_est %= n
    return m_est

def main():
    with socket.create_connection((HOST, PORT)) as s:
        f = s.makefile("rwb", buffering=0)

        # First banner: {"n": n, "c": key_c, "iv": ivhex, "ct": cthex}
        first = recv_json(f)
        n = int(first["n"])
        key_c = int(first["c"])
        iv_hex = first["iv"]
        ct_hex = first["ct"]

        # Recover key_m with bit-oracle
        key_m = recover_m(f, n, key_c, e=65537)

        # After 1024 oracle rounds, server prints key_m line; we do not depend on it.

        # Decrypt flag
        flag = aes_decrypt_from_key_m(key_m, iv_hex, ct_hex)
        sys.stdout.write(flag.decode(errors="ignore") + "\n")

if __name__ == "__main__":
    main()
