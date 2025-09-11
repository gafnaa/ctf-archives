#!/usr/bin/env python3

from pwn import *

# --- Configuration ---
# Set to True to connect to a remote server, False for a local process.
USE_REMOTE = True
REMOTE_HOST = "challs.watctf.org"
REMOTE_PORT = 2333
LOCAL_PROCESS = "./target/release/permutation_oracle" # Change this to the compiled binary name

# If you have the source and want to run it via cargo
# LOCAL_PROCESS = "cargo run --release"

# --- FNV1a_64 Hash Implementation (to match Rust code) ---
def fnv1a_64(data):
    """Computes the 64-bit FNV-1a hash."""
    h = 0xcbf29ce484222325
    for byte in data:
        h ^= byte
        h = (h * 0x100000001b3) & 0xffffffffffffffff
    return h

def do_hash(x):
    """Hashes an integer like the Rust program does."""
    # x is an i32, so 4 bytes, little-endian, signed
    return fnv1a_64(x.to_bytes(4, byteorder='little', signed=True))

def get_process():
    """Starts the connection to the remote server or local process."""
    if USE_REMOTE:
        return remote(REMOTE_HOST, REMOTE_PORT)
    else:
        # Use a shell to correctly handle commands like 'cargo run'
        return process(LOCAL_PROCESS, shell=True)

def get_candidate_pair(p, l):
    """
    Queries the oracle repeatedly with a given list `l` to find the two
    possible output values.
    """
    perm_str = " ".join(map(str, l))
    candidates = set()
    
    # Query up to 20 times to find two different values.
    # This is usually enough to overcome the randomness.
    for _ in range(20):
        p.sendlineafter(b"Enter your choice: ", b"1")
        p.sendlineafter(b"Enter the permutation seperated by spaces: ", perm_str.encode())
        response_line = p.recvline()
        try:
            value = int(response_line.strip().split(b" ")[-1])
            candidates.add(value)
            if len(candidates) == 2:
                break
        except (ValueError, IndexError):
            log.warning(f"Could not parse oracle response: {response_line}")
            continue # Try again
    
    if not candidates:
        log.error("Failed to get any valid response from the oracle.")
        return None
        
    return candidates


def main():
    """Main logic to solve the challenge."""
    # 1. Pre-compute hash buckets
    log.info("Pre-computing hash buckets...")
    HASH_SIZE = 32
    buckets = [[] for _ in range(HASH_SIZE)]
    for i in range(256):
        h = do_hash(i) % HASH_SIZE
        buckets[h].append(i)

    # 2. Connect to the process
    p = get_process()
    p.recvuntil(b"Welcome to the Permutation Oracle.\n")

    secret_perm = [-1] * 256
    log.info("Starting to reconstruct the secret permutation...")

    # 3. Determine each element of the secret permutation
    for k in range(256):
        h = do_hash(k) % HASH_SIZE
        bucket = buckets[h]

        # Find two other distinct numbers in the same bucket to use for flushing
        w, z = -1, -1
        for num in bucket:
            if num != k:
                if w == -1:
                    w = num
                else:
                    z = num
                    break
        
        if w == -1 or z == -1:
            log.error(f"Could not find enough collision partners for {k} in bucket {h}.")
            p.close()
            return
            
        # Construct lists that will pass the flawed checker
        list1 = ([k, w] * 128)
        list2 = ([k, z] * 128)

        # Get candidate sets by querying the oracle
        cand1 = get_candidate_pair(p, list1)
        cand2 = get_candidate_pair(p, list2)
        
        if cand1 is None or cand2 is None:
            log.error(f"Failed to get candidate pairs for k={k}. Aborting.")
            p.close()
            return

        # The intersection of the sets reveals the true value for cipherperm[k]
        intersection = cand1.intersection(cand2)
        
        if len(intersection) == 1:
            value = intersection.pop()
            secret_perm[k] = value
        else:
            log.warning(f"Intersection for k={k} was not unique (size {len(intersection)}). This may cause issues.")
            # Take a guess, it's likely one of the values.
            if intersection:
                secret_perm[k] = intersection.pop()
            else:
                log.error(f"Intersection for k={k} was empty. Cannot proceed.")
                p.close()
                return

        if (k + 1) % 16 == 0:
            log.info(f"Discovered {k+1}/256 values of the permutation.")

    log.success("Successfully reconstructed the secret permutation!")
    log.info(f"Secret: {secret_perm}")

    # 4. Submit the final guess
    final_guess_str = " ".join(map(str, secret_perm))
    p.sendlineafter(b"Enter your choice: ", b"2")
    p.sendlineafter(b"Enter the permutation seperated by spaces: ", final_guess_str.encode())

    # 5. Correctly parse the flag
    response = p.recvall(timeout=2).decode()
    
    if "Good job!" in response:
        # Extract the flag from the line
        for line in response.split('\n'):
            if "Good job!" in line:
                flag = line.split(":")[-1].strip()
                log.success(f"Flag: {flag}")
                break
    elif "Unfortunately, wrong" in response:
        log.error("The reconstructed permutation was incorrect.")
    else:
        log.warning(f"Unexpected final response from server:\n{response}")

    p.close()

if __name__ == "__main__":
    main()

