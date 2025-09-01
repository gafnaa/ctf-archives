from pwn import *

# --- MT19937 Constants ---
(w, n, m, r) = (32, 624, 397, 31)
a = 0x9908B0DF
(u, d) = (11, 0xFFFFFFFF)
(s, b) = (7, 0x9D2C5680)
(t, c) = (15, 0xEFC60000)
l = 18
f = 1812433253
lower_mask = (1 << r) - 1
upper_mask = (~lower_mask) & ((1 << w) - 1)

# --- MT19937 Core Functions ---

def _undo_right_shift(res, shift):
    """Reverses a right shift operation used in tempering."""
    tmp = res
    # Iteratively recover bits from MSB down
    for _ in range(w // shift + 1):
        tmp = res ^ (tmp >> shift)
    return tmp

def _undo_left_shift(res, shift, mask):
    """Reverses a masked left shift operation used in tempering."""
    tmp = res
    # Iteratively recover bits from LSB up
    for _ in range(w // shift + 1):
        tmp = res ^ ((tmp << shift) & mask)
    return tmp

def untemper(y):
    """Reverses the MT19937 tempering function to recover a state value from an output."""
    y = _undo_right_shift(y, l)
    y = _undo_left_shift(y, t, c)
    y = _undo_left_shift(y, s, b)
    y = _undo_right_shift(y, u)
    return y

def temper(y):
    """Applies the MT19937 tempering function to a state value to produce an output."""
    y ^= (y >> u)
    y ^= (y << s) & b
    y ^= (y << t) & c
    y ^= (y >> l)
    return y & ((1 << w) - 1)

def twist(mt_state):
    """Applies the MT19937 state twist function."""
    new_state = list(mt_state)
    for i in range(n):
        # The standard MT19937 algorithm uses a bitwise OR, not addition.
        # Using '|' instead of '+' resolves potential 1-bit ambiguities.
        x = (new_state[i] & upper_mask) | (new_state[(i + 1) % n] & lower_mask)
        xA = x >> 1
        if (x % 2) != 0:
            xA ^= a
        new_state[i] = (new_state[(i + m) % n] ^ xA) & ((1 << w) - 1)
    return new_state

# --- Challenge Configuration ---
HOST = "20.6.89.33"
PORT = 8054

def solve():
    """
    Solves the challenge by correctly synchronizing the server's two MT19937
    generators. It does this by recovering the initial state of the `random`
    generator, calculating its state after 624 outputs (the "twisted" state),
    and then feeding the server a sequence of inputs that forces its `wack`
    generator into an identical version of that final state.
    """
    
    # --- Stage 1: Collect 624 outputs to determine the generator's state ---
    log.info("Stage 1: Collecting 624 numbers to recover PRNG state...")
    p = remote(HOST, PORT)
    p.recvuntil(b'Find the rabbit!\n')

    server_outputs = []
    # Send dummy '0's to satisfy the prompts while we collect data.
    for i in range(n):
        p.recvuntil(b'>> ')
        p.sendline(b'0')
        try:
            num_str = p.recvline().strip()
            num = int(num_str)
            server_outputs.append(num)
        except (ValueError, IndexError):
            log.error(f"Stage 1 failed: Could not parse number on round {i}")
            p.close()
            return
            
    log.success("Collected 624 outputs from the server.")
    p.close()

    # --- Stage 2: Calculate the target input sequence ---
    log.info("Stage 2: Reconstructing server state and calculating attack vector...")
    
    # 2a: Recover the state of the server's `random` generator from our recon run.
    s_initial = [untemper(y) for y in server_outputs]
    
    # 2b: Calculate the state at the START of our attack connection. This is the
    # state after the first 624 outputs were generated during recon.
    s_at_attack_start = twist(s_initial)

    # 2c: Calculate the state of the `random` generator at the START
    # of the rabbit calculation. This is the state after ANOTHER 624 outputs
    # have been generated during our attack phase. This is the state we need to target.
    s_at_rabbit_calc = twist(s_at_attack_start)

    # 2d: We want the 'wack' generator's state to be IDENTICAL to the 'random'
    # generator's state. The previous cyclic shift was incorrect.
    wack_target_state = s_at_rabbit_calc

    # 2e: To force 'wack' into this state, we must send the *tempered* version
    # of each state word as our input during the attack phase.
    input_sequence = [temper(s) for s in wack_target_state]

    log.success("Calculated target input sequence.")

    # --- Stage 3: Final attack with the calculated sequence ---
    log.info("Stage 3: Connecting for the final attack run...")
    p = remote(HOST, PORT)
    p.recvuntil(b'Find the rabbit!\n')
    p.recvuntil(b'>> ') # Consume the very first prompt to prepare for sending.

    # To avoid the server's 2-second timeout, which can be triggered by
    # network latency over 624 round-trips, we pipeline all inputs.
    # We send them all at once, separated by newlines.
    log.info("Pipelining all 624 inputs to avoid server timeout...")
    payload = b'\n'.join(str(num).encode() for num in input_sequence)
    p.sendline(payload)

    log.success("Synchronization complete. All inputs sent.")
    log.info("The calculated 'rabbit' value should be 0. Waiting for the flag...")

    try:
        final_output = p.recvall(timeout=5).decode()
        print("\n" + "="*50)
        print("      Server's Final Response")
        print("="*50)
        print(final_output)
        print("="*50)
    except EOFError:
        log.warning("Connection closed by server. This is expected after winning.")
    finally:
        p.close()

if __name__ == "__main__":
    solve()

