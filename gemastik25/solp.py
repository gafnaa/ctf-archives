

from pwn import remote
import re
import time
import random

HOST = "18.143.31.243"
PORT = 9054
TIMEOUT = 6

def extract_integers(s):
    return [int(x) for x in re.findall(r'-?\d+', s)]

def run_strategy(strategy_name, initial_dummy):
    """
    strategy_name: "one_behind", "two_behind", "send_same", "random_dummy"
    initial_dummy: int to send for first prompt
    """
    print(f"\n[*] Strategy: {strategy_name}, initial_dummy={initial_dummy}")
    try:
        r = remote(HOST, PORT, timeout=10)
    except Exception as e:
        print("[-] connect failed:", e)
        return False, None

    observed = []   # printed numbers we see
    sent = []       # numbers we sent

    def recv_until_prompt():
        data = b""
        try:
            # read until '>> ' prompt or timeout
            data = r.recvuntil(b">> ", timeout=TIMEOUT)
        except Exception as e:
            # fall back to recvall chunk
            try:
                data = r.recv(timeout=1)
            except:
                data = b""
        return data.decode(errors='ignore')

    # read initial banner and prompt
    banner = recv_until_prompt()
    #print("[<] banner:", banner.replace('\n','\\n'))
    # send first dummy
    r.sendline(str(initial_dummy).encode())
    sent.append(initial_dummy)

    # loop for up to 624 iterations; after each send the server prints a random value (or maybe more lines)
    for i in range(624):
        # read lines until we get a new prompt or an integer
        try:
            # server prints a number then prompt; try recvline
            line = r.recvline(timeout=TIMEOUT)
        except Exception:
            line = b''
        if not line:
            # try to read until prompt
            try:
                more = r.recvuntil(b">> ", timeout=TIMEOUT)
                chunk = more.decode(errors='ignore')
            except Exception:
                chunk = ''
        else:
            chunk = line.decode(errors='ignore')

        # collect ints in chunk
        ints = extract_integers(chunk)
        if ints:
            # assume the last integer printed is the RNG output for this iteration
            observed.append(ints[-1])
            print(f"[<] observed #{len(observed)}: {ints[-1]}")
        else:
            # no integer, print raw for debugging
            if chunk.strip():
                print("[<] (text)", chunk.strip())

        # decide what to send next based on strategy
        to_send = 0
        if strategy_name == "one_behind":
            # send last observed (one step behind)
            if len(observed) >= 1:
                to_send = observed[-1]
            else:
                to_send = initial_dummy
        elif strategy_name == "two_behind":
            if len(observed) >= 2:
                to_send = observed[-2]
            elif len(observed) >= 1:
                to_send = observed[-1]
            else:
                to_send = initial_dummy
        elif strategy_name == "send_same":
            # send exactly what we just sent again
            to_send = sent[-1] if sent else initial_dummy
        elif strategy_name == "random_dummy":
            to_send = random.getrandbits(32)
        else:
            to_send = observed[-1] if observed else initial_dummy

        # send it (unless we're at end)
        try:
            r.sendline(str(to_send).encode())
            sent.append(to_send)
            print(f"[>] sent: {to_send} (iter {i})")
        except Exception as e:
            print("[-] send failed:", e)
            break

    # after loop, read remainder
    out = b""
    try:
        while True:
            part = r.recv(timeout=1)
            if not part:
                break
            out += part
    except Exception:
        pass

    text = out.decode(errors='ignore')
    print("[*] End session output:")
    print(text)
    r.close()

    # quick check if flag printed
    if "flag" in text.lower() or "You found the rabbit!" in text or "ribbit" in text:
        return True, text
    return False, text

def main():
    strategies = ["one_behind", "two_behind", "send_same", "random_dummy"]
    # you can add more dummy candidates here; small set because brute-forcing 2^32 is impossible
    dummy_candidates = [0, 1, 4294967295, random.getrandbits(32), 123456789, 0xDEADBEEF]

    tries = 200  # total attempts (can increase)
    attempt = 0
    for attempt in range(tries):
        strat = random.choice(strategies)
        dummy = random.choice(dummy_candidates)
        success, output = run_strategy(strat, dummy)
        if success:
            print("[+] Success! Output:\n", output)
            return
        time.sleep(0.2)  # small delay between connections

    print("[-] Done tries; no success. Try other ideas (see notes).")

if __name__ == "__main__":
    main()
