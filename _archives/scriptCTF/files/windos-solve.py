#!/usr/bin/env python3

# Import necessary libraries
from pwn import *
from collections import Counter
from sortedcontainers import SortedList
import math

# --- Connection Details ---
HOST = 'play.scriptsorcerers.xyz'
PORT = 10091

# --- Problem Parameters ---
n = 1000000
window_size = n // 2
# The problem states median is at index floor(k/2) for a window of size k
MEDIAN_IDX = window_size // 2 
# Maximum possible value for a number in the list is 100,000
MAX_A = 100001 

# --- Global variables for Round 8 precomputation ---
phi = list(range(MAX_A))
divisors = [[] for _ in range(MAX_A)]

def precompute_gcd_helpers():
    """
    Precomputes Euler's totient function (phi) and a list of divisors
    for all numbers up to MAX_A to speed up Round 8.
    """
    info("Starting precomputation for Round 8...")
    # Sieve to calculate Euler's totient function
    for i in range(2, MAX_A):
        if phi[i] == i: # i is a prime number
            for j in range(i, MAX_A, i):
                phi[j] -= phi[j] // i
    
    # Sieve to find all divisors for each number
    for i in range(1, MAX_A):
        for j in range(i, MAX_A, i):
            divisors[j].append(i)
    info("Precomputation finished.")

# ===============================================
#               ROUND SOLVERS
# ===============================================

## Round 1: Sums
def solve_round_1_sums(a):
    results = []
    current_sum = sum(a[:window_size])
    results.append(current_sum)
    # Slide the window, updating the sum in O(1) time
    for i in range(1, n - window_size + 1):
        current_sum = current_sum - a[i-1] + a[i + window_size - 1]
        results.append(current_sum)
    return results

## Round 2: Xors
def solve_round_2_xors(a):
    results = []
    current_xor = 0
    for x in a[:window_size]:
        current_xor ^= x
    results.append(current_xor)
    # Slide the window, updating the XOR sum in O(1) time
    for i in range(1, n - window_size + 1):
        current_xor = current_xor ^ a[i-1] ^ a[i + window_size - 1]
        results.append(current_xor)
    return results

## Round 3: Means
def solve_round_3_means(sums):
    # Reuse the sums from Round 1 for an easy O(1) calculation
    return [s // window_size for s in sums]

## Round 4: Median
def solve_round_4_median(a):
    results = []
    # SortedList provides O(log k) add/remove operations
    sl = SortedList(a[:window_size])
    results.append(sl[MEDIAN_IDX])
    for i in range(1, n - window_size + 1):
        sl.remove(a[i-1])
        sl.add(a[i + window_size - 1])
        results.append(sl[MEDIAN_IDX])
    return results

## Round 5: Modes
def solve_round_5_modes(a):
    results = []
    counts = Counter(a[:window_size])
    # A SortedList of (frequency, value) tuples automatically finds the
    # mode and handles the tie-breaking rule (largest value).
    sl = SortedList((freq, val) for val, freq in counts.items())
    results.append(sl[-1][1])

    for i in range(1, n - window_size + 1):
        leaving, entering = a[i-1], a[i + window_size - 1]

        # Update for the element leaving the window
        sl.remove((counts[leaving], leaving))
        counts[leaving] -= 1
        if counts[leaving] > 0:
            sl.add((counts[leaving], leaving))
        else:
            del counts[leaving]
        
        # Update for the element entering the window
        old_freq = counts.get(entering, 0)
        if old_freq > 0:
            sl.remove((old_freq, entering))
        counts[entering] = old_freq + 1
        sl.add((counts[entering], entering))

        results.append(sl[-1][1])
    return results

## Round 6: Mex (Minimum Excluded)
def solve_round_6_mex(a):
    results = []
    counts = Counter(a[:window_size])
    
    # Find the initial mex
    mex = 0
    while mex in counts:
        mex += 1
    results.append(mex)

    # Slide the window and update mex efficiently
    for i in range(1, n - window_size + 1):
        leaving, entering = a[i-1], a[i + window_size - 1]

        counts[leaving] -= 1
        if counts[leaving] == 0:
            del counts[leaving]
            if leaving < mex:
                mex = leaving # A new, smaller mex is now possible
        
        counts[entering] = counts.get(entering, 0) + 1
        if counts[entering] == 1 and entering == mex:
            # The old mex is now in the set, find the next one
            while mex in counts:
                mex += 1
        
        results.append(mex)
    return results

## Round 7: Number of Distinct Numbers
def solve_round_7_distinct(a):
    results = []
    counts = Counter(a[:window_size])
    distinct_count = len(counts)
    results.append(distinct_count)

    for i in range(1, n - window_size + 1):
        leaving, entering = a[i-1], a[i + window_size - 1]

        # Update for leaving element
        counts[leaving] -= 1
        if counts[leaving] == 0:
            distinct_count -= 1
        
        # Update for entering element
        if counts.get(entering, 0) == 0:
            distinct_count += 1
        counts[entering] = counts.get(entering, 0) + 1
        
        results.append(distinct_count)
    return results

## Round 8: Sum of Pairwise GCD
def solve_round_8_gcd_sum(a):
    results = []
    counts = [0] * MAX_A
    current_sum = 0
    
    # Initialize the first window by adding elements one by one
    for x in a[:window_size]:
        # Contribution of adding x is sum_{y in current set} gcd(x,y)
        # This can be calculated as sum_{d|x} phi(d) * count_multiples_of_d
        for d in divisors[x]:
            current_sum += phi[d] * counts[d]
        for d in divisors[x]:
            counts[d] += 1
            
    results.append(current_sum)

    # Slide the window
    for i in range(1, n - window_size + 1):
        leaving, entering = a[i-1], a[i + window_size - 1]

        # First, calculate the change from removing the 'leaving' element
        for d in divisors[leaving]:
            current_sum -= phi[d] * (counts[d] - 1)
        # Then, update the counts array
        for d in divisors[leaving]:
            counts[d] -= 1
            
        # Next, calculate the change from adding the 'entering' element
        for d in divisors[entering]:
            current_sum += phi[d] * counts[d]
        # Finally, update the counts array
        for d in divisors[entering]:
            counts[d] += 1

        results.append(current_sum)
    return results

# ===============================================
#                   MAIN LOGIC
# ===============================================

def main():
    # Run precomputation for the GCD round
    precompute_gcd_helpers()

    # Connect to the server
    io = remote(HOST, PORT)
    
    # Receive the list of numbers
    io.recvuntil(b"every window.\n")
    line = io.recvline().strip()
    a = list(map(int, line.split()))
    info(f"Received {len(a)} numbers. First 5: {a[:5]}")

    # Solve each round sequentially
    
    info("Solving Round 1: Sums...")
    sums = solve_round_1_sums(a)
    io.sendlineafter(b"Sums!\n", ' '.join(map(str, sums)).encode())
    info("Round 1 passed. ✅")

    info("Solving Round 2: Xors...")
    xors = solve_round_2_xors(a)
    io.sendlineafter(b"Xors!\n", ' '.join(map(str, xors)).encode())
    info("Round 2 passed. ✅")

    info("Solving Round 3: Means...")
    means = solve_round_3_means(sums)
    io.sendlineafter(b"Means!\n", ' '.join(map(str, means)).encode())
    info("Round 3 passed. ✅")
    
    info("Solving Round 4: Median...")
    medians = solve_round_4_median(a)
    io.sendlineafter(b"Median!\n", ' '.join(map(str, medians)).encode())
    info("Round 4 passed. ✅")
    
    info("Solving Round 5: Modes...")
    modes = solve_round_5_modes(a)
    io.sendlineafter(b"Modes!\n", ' '.join(map(str, modes)).encode())
    info("Round 5 passed. ✅")

    info("Solving Round 6: Mex...")
    mexes = solve_round_6_mex(a)
    io.sendlineafter(b"Mex (minimum excluded)!\n", ' '.join(map(str, mexes)).encode())
    info("Round 6 passed. ✅")

    info("Solving Round 7: # of Distinct Numbers...")
    distincts = solve_round_7_distinct(a)
    io.sendlineafter(b"# of Distinct Numbers!\n", ' '.join(map(str, distincts)).encode())
    info("Round 7 passed. ✅")

    info("Solving Round 8: Sum of pairwise GCD...")
    gcd_sums = solve_round_8_gcd_sum(a)
    io.sendlineafter(b"Sum of pairwise GCD!\n", ' '.join(map(str, gcd_sums)).encode())
    info("Round 8 passed. ✅")

    # Receive and print the flag
    flag = io.recvline().decode().strip()
    success(f"Flag: {flag} 🎉")
    io.close()


if __name__ == "__main__":
    main()