import base64
import json
import itertools

# --- Challenge-Specific Functions ---

def hash_char(hash_c, key_c):
    """The custom character hashing function from the CTF."""
    return chr(pow(ord(hash_c), ord(key_c), 26) + 65)

def has(inp, jwt_key):
    """The custom JWT signing function from the CTF."""
    hashed = ""
    if not jwt_key:
        return ""
    for i in range(64):
        hashed += hash_char(inp[i % len(inp)], jwt_key[i % len(jwt_key)])
    return hashed

# --- Key Recovery and Token Forging Logic ---

def solve_k_ord(inp_ord, sig_val):
    """
    Solves for possible ord values of a key character.
    'sig_val' is ord(sig_char) - 65.
    Returns a list of possible integer values for ord(key_char).
    """
    solutions = []
    for k in range(256):  # Test all possible byte values for the key character
        try:
            if pow(inp_ord, k, 26) == sig_val:
                solutions.append(k)
        except ValueError:
            # This can happen if inp_ord is 0 and k is 0, for example.
            # In the context of this hash, ord(0) isn't used.
            pass
    return solutions

def find_key_and_forge_token(token):
    """
    Analyzes the token to find the key, then forges a new token.
    """
    print("[*] Starting analysis of the provided token...")
    try:
        header_b64, payload_b64, signature = token.split('.')
        signing_input = f"{header_b64}.{payload_b64}"
    except ValueError:
        print("[!] ERROR: The token string is not in a valid JWT format (header.payload.signature).")
        return

    # 1. Find all possible ord values for each of the 64 signature positions
    print("[*] Calculating possible key character ordinals for all 64 signature positions...")
    possible_ords_at_pos = []
    for i in range(64):
        inp_ord = ord(signing_input[i % len(signing_input)])
        sig_val = ord(signature[i]) - 65
        
        solutions = solve_k_ord(inp_ord, sig_val)
        if not solutions:
            print(f"[!] ERROR: Mathematical impossibility found at index {i}.")
            print(f"    Input char: '{signing_input[i % len(signing_input)]}' (ord={inp_ord})")
            print(f"    Signature char: '{signature[i]}' (val={sig_val})")
            print(f"    The equation pow({inp_ord % 26}, k, 26) == {sig_val} has NO solution for k.")
            print("[!] Please double-check the JWT for typos. Aborting.")
            return
        possible_ords_at_pos.append(solutions)

    # 2. Iterate through possible key lengths to find the correct one
    print("[*] Searching for the correct key length (1-30)...")
    for key_len in range(1, 31):
        candidate_key_ords = []
        is_consistent = True
        for i in range(key_len):
            # Intersect all possibilities for this key index
            common_ords = set(possible_ords_at_pos[i])
            for j in range(i + key_len, 64, key_len):
                common_ords.intersection_update(possible_ords_at_pos[j])
            
            if not common_ords:
                is_consistent = False
                break
            candidate_key_ords.append(sorted(list(common_ords)))
        
        if is_consistent:
            print(f"\n[*] Found a plausible key length: {key_len}. Verifying key...")
            # Usually CTF keys are printable. We prioritize those.
            printable_candidates = [[o for o in ords if 32 <= o <= 126] for ords in candidate_key_ords]
            
            if not all(printable_candidates):
                print(f"    Key of length {key_len} seems to contain non-printable characters. Skipping for now.")
                continue

            # Iterate through all possible printable key combinations
            for key_ord_tuple in itertools.product(*printable_candidates):
                jwt_key = "".join(map(chr, key_ord_tuple))
                
                # 3. Verify the found key by re-calculating the original signature
                if has(signing_input, jwt_key) == signature:
                    print(f"\n{'='*50}")
                    print(f"  ✅ SUCCESS! Discovered JWT Key: '{jwt_key}'")
                    print(f"{'='*50}")
                    
                    # 4. Forge the admin token
                    print("\n[*] Forging new token with admin privileges...")
                    
                    # Decode header to preserve it
                    new_payload = {"username": "gafna", "password": "gafna", "admin": "true"}
                    
                    # Create the new payload part
                    new_payload_json = json.dumps(new_payload, separators=(',', ':'))
                    new_payload_b64 = base64.urlsafe_b64encode(new_payload_json.encode()).rstrip(b'=').decode()
                    
                    # Create the new signing input
                    new_signing_input = f"{header_b64}.{new_payload_b64}"
                    
                    # Sign with the found key
                    new_signature = has(new_signing_input, jwt_key)
                    
                    # Assemble the final token
                    admin_token = f"{header_b64}.{new_payload_b64}.{new_signature}"
                    
                    print("\n" + "="*50)
                    print("          Forged Admin Token")
                    print("="*50 + "\n")
                    print(admin_token)
                    return # Mission accomplished

    print("\n[!] Could not find a valid key. The provided token may be incorrect or the key is longer than 30 characters.")


# --- Main Execution ---
if __name__ == "__main__":
    # Replace this with the correct token from the CTF challenge
    ctf_token = "eyJhbGciOiAiQURNSU5IQVNIIiwgInR5cCI6ICJKV1QifQ.eyJ1c2VybmFtZSI6ICJnYWZuYSIsICJwYXNzd29yZCI6ICJnYWZuYSIsICJhZG1pbiI6ICJmYWxzZSJ9.JZOAYHBBBBNBDDQABXBFJOABZBLBBSOBVLBWVBQRSJJBOJYXDQZBEIRQBSOOFFWB"
    find_key_and_forge_token(ctf_token)