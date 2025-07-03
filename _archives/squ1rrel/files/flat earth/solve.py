import json

def solve_round(challenge):
    # The proof is fixed: A = alpha*G1, B = beta*G2, C = O
    proof = {
        "A": "(2693, 4312)",  # G1 (but alpha*G1 is same as G1 since alpha is scalar; adjust if alpha is known)
        "B": "(633*v + 6145, 7372*v + 109)",  # G2 (beta*G2 is same as G2 if beta is scalar)
        "C": "O"
    }
    return {"proof": proof}

# Example usage:
challenge = {
    "L": "(3507, 2155)",
    "R": "(5467*v + 6211, 3846*v + 1361)",
    "Q": "(768, 2210)"
}
response = solve_round(challenge)
print(json.dumps(response))