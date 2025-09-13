#!/usr/bin/env python3

import pwn
import json
import base64
import hashlib
from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der, sigdecode_der

# --- Server Interaction ---
# Uncomment the line for the actual server
HOST, PORT = "0.cloud.chals.io", 19521
# To test locally if you have the challenge file:
# HOST, PORT = "localhost", 12345

# --- secp256k1 curve parameters from the challenge ---
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def get_ticket(p):
    """
    Requests a ticket from the server and parses the response.
    """
    p.sendlineafter(b"Choose an action:\n", b"1")
    p.recvuntil(b"ticket: ")
    ticket_b64 = p.recvline().strip().decode()
    
    ticket_json = base64.b64decode(ticket_b64)
    ticket_data = json.loads(ticket_json)
    
    # Extract ticket ID
    ticket_id = ticket_data["payload"]["ticket_id"]
    
    # Extract signature (r, s)
    sig_hex = ticket_data["signature"]
    r = int(sig_hex[:64], 16)
    s = int(sig_hex[64:], 16)
    
    # Create the message that was signed
    payload_bytes = json.dumps({"ticket_id": ticket_id}, separators=(',', ':'), sort_keys=True).encode()
    msg_hash = int.from_bytes(hashlib.sha256(payload_bytes).digest(), 'big')
    
    print(f"[*] Got Ticket ID: {str(ticket_id)[:20]}... | r: {str(r)[:20]}...")
    return {'id': ticket_id, 'r': r, 's': s, 'z': msg_hash}

def solve_for_recurrence(tickets):
    """
    Solves for the linear recurrence coefficients C1 and C2
    using four consecutive ticket IDs.
    Recurrence: T_i = C1*T_{i-1} + C2*T_{i-2}
    """
    T1, T2, T3, T4 = [t['id'] for t in tickets]
    
    # We need to solve the system:
    # T3 = C1*T2 + C2*T1
    # T4 = C1*T3 + C2*T2
    # In matrix form: A * x = b, where x = [C1, C2]^T
    
    # Matrix A
    A_mat = [
        [T2, T1],
        [T3, T2]
    ]
    # Vector b
    b_vec = [T3, T4]
    
    # Calculate determinant and its inverse
    det = (A_mat[0][0] * A_mat[1][1] - A_mat[0][1] * A_mat[1][0]) % N
    det_inv = pow(det, -1, N)
    
    # Calculate inverse of A
    A_inv = [
        [ (A_mat[1][1] * det_inv) % N, (-A_mat[0][1] * det_inv) % N],
        [(-A_mat[1][0] * det_inv) % N, ( A_mat[0][0] * det_inv) % N]
    ]
    
    # Solve for x = A_inv * b
    C1 = (A_inv[0][0] * b_vec[0] + A_inv[0][1] * b_vec[1]) % N
    C2 = (A_inv[1][0] * b_vec[0] + A_inv[1][1] * b_vec[1]) % N
    
    print(f"[+] Found recurrence coeffs: C1={C1}, C2={C2}")
    return C1, C2

def solve_for_privkey(tickets, C1, C2):
    """
    Solves for the ECDSA private key 'd' using the recurrence
    and three signatures.
    """
    t1, t2, t3 = tickets[0], tickets[1], tickets[2]

    # From s*k = z + r*d, we get k = s_inv*(z + r*d)
    # Substitute into k3 = C1*k2 + C2*k1
    # s3_inv*(z3+r3*d) = C1*s2_inv*(z2+r2*d) + C2*s1_inv*(z1+r1*d)
    # This is a linear equation in 'd'.
    
    s1_inv = pow(t1['s'], -1, N)
    s2_inv = pow(t2['s'], -1, N)
    s3_inv = pow(t3['s'], -1, N)

    # Group terms with 'd' on one side and constants on the other
    # d * (r3*s3_inv - C1*r2*s2_inv - C2*r1*s1_inv) = C1*z2*s2_inv + C2*z1*s1_inv - z3*s3_inv
    
    d_coeff = (t3['r'] * s3_inv - C1 * t2['r'] * s2_inv - C2 * t1['r'] * s1_inv) % N
    const_term = (C1 * t2['z'] * s2_inv + C2 * t1['z'] * s1_inv - t3['z'] * s3_inv) % N
    
    d = (const_term * pow(d_coeff, -1, N)) % N
    
    print(f"[+] Found private key: {d}")
    return d

def forge_ticket(priv_key):
    """
    Uses the recovered private key to forge a ticket for the flag.
    """
    # This is the target ID to get the flag
    target_id = int.from_bytes(hashlib.sha256(b"I'd like the flag please").digest(), 'big')
    print(f"[*] Forging ticket for target ID: {target_id}")

    payload = {"ticket_id": target_id}
    payload_bytes = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode()
    
    # Create a signing key object from the raw private key integer
    sk = SigningKey.from_secret_exponent(priv_key, curve=SECP256k1, hashfunc=hashlib.sha256)
    
    # ecdsa library handles random k generation and signing
    signature_der = sk.sign(payload_bytes)
    
    # The server expects a raw (r,s) signature, not DER format
    r, s = sigdecode_der(signature_der, SECP256k1.order)

    # Format the signature and ticket for the server
    sig_hex = f"{r:064x}{s:064x}"
    
    forged_ticket_data = {
        "payload": payload,
        "signature": sig_hex,
    }

    ticket_json = json.dumps(forged_ticket_data, separators=(',', ':'), sort_keys=True).encode()
    return base64.b64encode(ticket_json).decode()

def main():
    p = pwn.remote(HOST, PORT)
    
    # 1. Collect data
    print("[*] Collecting 4 tickets to analyze the RNG...")
    tickets = [get_ticket(p) for _ in range(4)]
    
    # 2. Find the recurrence relation
    C1, C2 = solve_for_recurrence(tickets)
    
    # 3. Recover the private key
    priv_key = solve_for_privkey(tickets, C1, C2)
    
    # 4. Forge the winning ticket
    winning_ticket = forge_ticket(priv_key)
    
    # 5. Claim the prize
    print("[*] Sending forged ticket to claim the flag...")
    p.sendlineafter(b"Choose an action:\n", b"2")
    p.sendlineafter(b"Enter your ticket:\n", winning_ticket.encode())
    
    # Read and print the final prize/flag
    p.interactive()

if __name__ == "__main__":
    main()
