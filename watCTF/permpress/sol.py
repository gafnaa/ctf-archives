

from pwn import remote, context, log
import time
from collections import defaultdict, OrderedDict

HOST = "challs.watctf.org"
PORT = 2333
PERM_LEN = 256

context.log_level = "info"  # set to "debug" for verbose comms

def make_identity_perm():
    return " ".join(str(i) for i in range(PERM_LEN))

def recv_until_prompt(r):
    # read until the main menu prompt appears (best-effort)
    # the remote prints "Enter your choice: " before choice
    data = r.recvuntil(b"Enter your choice: ", timeout=5)
    return data

def give_permutation_and_sample(r, perm_str):
    """
    Send menu option 1 and the permutation string.
    Parse the single integer returned by the oracle.
    Returns the int or None on parse error.
    """
    # choose option 1
    r.sendline(b"1")
    # receive the "Enter the permutation" prompt
    r.recvuntil(b"Enter the permutation", timeout=3)
    # send permutation
    r.sendline(perm_str.encode())
    # read response line, should contain "... <num>"
    # example: The oracle has divined... 123
    try:
        line = r.recvline(timeout=3).decode(errors="ignore").strip()
    except Exception as e:
        log.warn(f"recvline fail: {e}")
        return None
    # try to parse integer in line
    for token in line.split():
        try:
            v = int(token)
            return v
        except:
            continue
    # if no integer found, return None
    log.warn(f"Couldn't parse integer from oracle response: {line}")
    return None

def guess_from_first_seen(order_seen):
    """
    Build a guess permutation by placing values in positions equal to
    the order they were first seen (heuristic).
    i.e., first seen value -> position 0, second seen -> position 1, ...
    This is a simple heuristic — not guaranteed correct but often useful
    as a first attempt in CTF experimental setups.
    """
    perm = [-1] * PERM_LEN
    # order_seen is iterable of unique values in first-seen order
    for idx, val in enumerate(order_seen):
        perm[idx] = val
    # fill remaining positions with values not yet used
    unused = [v for v in range(PERM_LEN) if v not in order_seen]
    j = 0
    for i in range(PERM_LEN):
        if perm[i] == -1:
            perm[i] = unused[j]
            j += 1
    return perm

def perm_to_str(perm):
    return " ".join(str(int(x)) for x in perm)

def attempt_guess(r, perm_guess_str):
    # choose option 2
    r.sendline(b"2")
    r.recvuntil(b"Enter the permutation", timeout=3)
    r.sendline(perm_guess_str.encode())
    # read response lines until menu or a line
    try:
        resp = r.recvline(timeout=5).decode(errors="ignore").strip()
        return resp
    except Exception as e:
        log.warn(f"attempt_guess recv failed: {e}")
        return None

def main():
    log.info(f"Connecting to {HOST}:{PORT} ...")
    r = remote(HOST, PORT, timeout=10)

    # read welcome/menu until prompt
    try:
        recv_until_prompt(r)
    except Exception as e:
        log.warn(f"Initial menu receive failed: {e}")
        # try to continue anyway

    # Strategy: sample identity permutation repeatedly until we've seen many unique values.
    identity = make_identity_perm()
    seen = OrderedDict()  # preserve first-seen order mapping value->count
    counts = defaultdict(int)
    max_queries = 4000   # adjustable; you can increase if needed
    target_unique = PERM_LEN

    log.info("Starting sampling using identity permutation. This will collect printed values.")
    for i in range(max_queries):
        v = give_permutation_and_sample(r, identity)
        if v is None:
            log.warn("No value received; trying to re-sync the menu.")
            # try to re-sync by reading until prompt
            try:
                recv_until_prompt(r)
            except:
                pass
            continue
        counts[v] += 1
        if v not in seen:
            seen[v] = 1
            log.info(f"First-seen new value {v} (total unique={len(seen)}/{target_unique})")
        else:
            seen[v] += 1
        if len(seen) >= target_unique:
            log.success("Collected all unique values at least once.")
            break
        # small sleep to avoid spamming too fast
        time.sleep(0.005)

    log.info(f"Sampling finished. Unique values seen: {len(seen)} out of {PERM_LEN}")
    # Print frequency table summary
    log.info("Frequencies (top 10):")
    freq_sorted = sorted(counts.items(), key=lambda kv: -kv[1])
    for val, cnt in freq_sorted[:10]:
        log.info(f"{val}: {cnt}")

    # Heuristic guess: place first-seen values in order of first appearance
    order_seen = list(seen.keys())
    guess_perm = guess_from_first_seen(order_seen)
    guess_str = perm_to_str(guess_perm)

    log.info("Submitting heuristic guess permutation (based on first-seen order)...")
    resp = attempt_guess(r, guess_str)
    if resp:
        log.info("Response to guess: " + resp)
    else:
        log.warn("No response after guess.")

    # If unsuccessful, the script keeps connection open and prints suggestion
    log.info("Done. If the guess failed, consider increasing sampling (max_queries),")
    log.info("or implement an alternative recovery strategy based on RNG-state exploitation /")
    log.info("oracles that reveal RNG output indices (if available).")
    r.interactive()

if __name__ == "__main__":
    main()
