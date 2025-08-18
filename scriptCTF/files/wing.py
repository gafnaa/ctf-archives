#!/usr/bin/env python3

# --- IMPORTS ---
from pwn import *
from collections import Counter
import sys

# --- Configuration ---
HOST = 'play.scriptsorcerers.xyz'
PORT = 10091
N = 1_000_000
WINDOW_SIZE = N // 2
MAX_VAL = 100001

# --- Solver Logic (Copied from previous answer) ---
# This part contains the efficient algorithms for each round.

# Precomputation for Round 8 (GCD Sum)
divs = [[] for _ in range(MAX_VAL)]
phi = list(range(MAX_VAL))

def precompute_gcd_helpers():
    phi[0] = 0
    for i in range(1, MAX_VAL):
        if i > 1 and phi[i] == i:
            for j in range(i, MAX_VAL, i):
                phi[j] -= phi[j] // i
        for j in range(i, MAX_VAL, i):
            divs[j].append(i)

def solve_sums(a):
    results = []
    current_sum = sum(a[0:WINDOW_SIZE])
    results.append(current_sum)
    for i in range(1, N - WINDOW_SIZE + 1):
        current_sum = current_sum - a[i - 1] + a[i + WINDOW_SIZE - 1]
        results.append(current_sum)
    return results

def solve_xors(a):
    results = []
    current_xor = 0
    for i in range(WINDOW_SIZE):
        current_xor ^= a[i]
    results.append(current_xor)
    for i in range(1, N - WINDOW_SIZE + 1):
        current_xor = current_xor ^ a[i - 1] ^ a[i + WINDOW_SIZE - 1]
        results.append(current_xor)
    return results

def solve_means(a):
    sum_results = solve_sums(a)
    return [s // WINDOW_SIZE for s in sum_results]

def solve_medians(a):
    bit = [0] * MAX_VAL
    def update(i, delta):
        i += 1
        while i < MAX_VAL:
            bit[i] += delta
            i += i & -i
    def find_kth(k):
        l, r, ans = 0, MAX_VAL - 1, -1
        while l <= r:
            m = (l + r) // 2
            s, i = 0, m + 1
            while i > 0:
                s += bit[i]; i -= i & -i
            if s >= k:
                ans, r = m, m - 1
            else:
                l = m + 1
        return ans
    results, median_pos = [], (WINDOW_SIZE + 1) // 2
    for i in range(WINDOW_SIZE): update(a[i], 1)
    results.append(find_kth(median_pos))
    for i in range(1, N - WINDOW_SIZE + 1):
        update(a[i - 1], -1); update(a[i + WINDOW_SIZE - 1], 1)
        results.append(find_kth(median_pos))
    return results

def solve_modes(a):
    results, freq, count_sets, max_freq = [], Counter(), [set() for _ in range(WINDOW_SIZE + 1)], 0
    def add(x):
        nonlocal max_freq
        old_c = freq[x]; freq[x] += 1; new_c = old_c + 1
        if old_c > 0: count_sets[old_c].remove(x)
        count_sets[new_c].add(x)
        if new_c > max_freq: max_freq = new_c
    def remove(x):
        nonlocal max_freq
        old_c = freq[x]; freq[x] -= 1; new_c = old_c - 1
        count_sets[old_c].remove(x)
        if not count_sets[old_c] and old_c == max_freq: max_freq -= 1
        if new_c > 0: count_sets[new_c].add(x)
    for i in range(WINDOW_SIZE): add(a[i])
    results.append(max(count_sets[max_freq]))
    for i in range(1, N - WINDOW_SIZE + 1):
        remove(a[i-1]); add(a[i + WINDOW_SIZE - 1])
        results.append(max(count_sets[max_freq]))
    return results

def solve_mex(a):
    results, counts, mex = [], [0] * (N + 2), 0
    for i in range(WINDOW_SIZE): counts[a[i]] += 1
    while counts[mex] > 0: mex += 1
    results.append(mex)
    for i in range(1, N - WINDOW_SIZE + 1):
        leaving, entering = a[i - 1], a[i + WINDOW_SIZE - 1]
        counts[leaving] -= 1
        if counts[leaving] == 0 and leaving < mex: mex = leaving
        counts[entering] += 1
        if entering == mex:
            while counts[mex] > 0: mex += 1
        results.append(mex)
    return results

def solve_distinct(a):
    results, counts = [], Counter()
    for i in range(WINDOW_SIZE): counts[a[i]] += 1
    results.append(len(counts))
    for i in range(1, N - WINDOW_SIZE + 1):
        leaving, entering = a[i - 1], a[i + WINDOW_SIZE - 1]
        counts[leaving] -= 1
        if counts[leaving] == 0: del counts[leaving]
        counts[entering] += 1
        results.append(len(counts))
    return results

def solve_gcd_sum(a):
    results, total_gcd_sum, multiple_counts = [], 0, [0] * MAX_VAL
    for x in a[:WINDOW_SIZE]:
        total_gcd_sum += sum(phi[d] * multiple_counts[d] for d in divs[x])
        for d in divs[x]: multiple_counts[d] += 1
    results.append(total_gcd_sum)
    for i in range(1, N - WINDOW_SIZE + 1):
        leaving, entering = a[i - 1], a[i + WINDOW_SIZE - 1]
        for d in divs[leaving]: multiple_counts[d] -= 1
        total_gcd_sum -= sum(phi[d] * multiple_counts[d] for d in divs[leaving])
        total_gcd_sum += sum(phi[d] * multiple_counts[d] for d in divs[entering])
        for d in divs[entering]: multiple_counts[d] += 1
        results.append(total_gcd_sum)
    return results

# --- Main Interaction Logic ---
def main():
    # Establish the connection
    p = remote(HOST, PORT)

    # Receive the line of numbers from the server
    p.recvuntil(b'numbers.\n') # Wait until the prompt right before the numbers
    line = p.recvline().strip()
    a = list(map(int, line.split()))
    log.success(f"Received and parsed {len(a)} numbers.")

    # Run precomputation for the hard GCD round
    log.info("Running precomputation for GCD round...")
    precompute_gcd_helpers()
    log.success("Precomputation finished.")

    # List of solver functions in the correct order
    solvers = [
        solve_sums, solve_xors, solve_means, solve_medians,
        solve_modes, solve_mex, solve_distinct, solve_gcd_sum
    ]

    # Loop through all 8 rounds
    for i, solver_func in enumerate(solvers):
        round_num = i + 1
        
        # Wait for the server's prompt for the current round
        prompt = p.recvuntil(f"Round {round_num}".encode())
        log.info(f"Received prompt for Round {round_num}")
        
        # Calculate the results
        results = solver_func(a)
        answer = ' '.join(map(str, results))
        
        # Send the answer
        p.sendline(answer.encode())
        log.success(f"Sent answer for Round {round_num}")

    # After the loop, receive and print the flag
    log.success("All rounds completed! Here is the flag:")
    flag = p.recvall(timeout=2).decode(errors='ignore').strip()
    print(f"\nFLAG: {flag}\n")
    p.close()

if __name__ == "__main__":
    main()