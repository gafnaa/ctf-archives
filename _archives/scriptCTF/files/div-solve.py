import time
from collections import defaultdict
from pwn import * # Import the pwntools library

# --- Configuration ---
HOST = "play.scriptsorcerers.xyz"
PORT = 10480
MAX_VAL = 200001 # Maximum possible value for a number in the list + 1

# --- Sieve for Smallest Prime Factor (SPF) ---
# This pre-computation helps factor numbers very quickly later on.
# spf[i] will store the smallest prime factor of i.
spf = list(range(MAX_VAL))

def sieve():
    """
    Generates the smallest prime factor for all numbers up to MAX_VAL.
    This is an optimized version of the Sieve of Eratosthenes.
    """
    print("Pre-computing smallest prime factors using a sieve...")
    # Start with 2, the first prime
    for i in range(2, int(MAX_VAL**0.5) + 1):
        # If i is its own smallest prime factor, it's a prime number
        if spf[i] == i:
            # Mark all multiples of i
            for j in range(i * i, MAX_VAL, i):
                # If j's smallest prime factor hasn't been set yet, set it to i
                if spf[j] == j:
                    spf[j] = i
    print("Sieve computation complete.")

def get_unique_prime_factors(n):
    """
    Returns a set of unique prime factors for a number n using the pre-computed SPF array.
    """
    factors = set()
    while n > 1:
        factor = spf[n]
        factors.add(factor)
        # Divide n by its smallest prime factor until it's no longer divisible
        while n % factor == 0:
            n //= factor
    return factors

def solve(numbers):
    """
    Finds the length of the longest subsequence with a GCD > 1.
    This is done by finding the prime factor that appears in the most numbers.
    """
    # A dictionary to store the frequency of each prime factor
    prime_factor_counts = defaultdict(int)

    print(f"Processing {len(numbers)} numbers...")
    for num in numbers:
        if num > 1:
            # Get the unique prime factors for the current number
            factors = get_unique_prime_factors(num)
            # Increment the count for each unique prime factor
            for factor in factors:
                prime_factor_counts[factor] += 1
    
    # If there are no common factors (e.g., all numbers are 1), the answer is 0.
    if not prime_factor_counts:
        return 0

    # The length of the longest subsequence is the highest frequency of any prime factor.
    max_length = max(prime_factor_counts.values())
    return max_length

def main():
    """
    Main function to connect to the server, handle I/O, and solve the challenge using pwntools.
    """
    # Pre-compute the sieve once
    sieve()

    try:
        # Connect to the server using pwntools
        p = remote(HOST, PORT)
        print(f"Connected to {HOST}:{PORT}")

        # Receive the initial banner and data
        # We'll receive until we see a line that is just numbers and spaces
        while True:
            line = p.recvline().decode().strip()
            print(f"Received: {line}")
            # Check if the line contains the list of numbers
            if line and all(c.isdigit() or c.isspace() for c in line):
                numbers = [int(n) for n in line.split()]
                
                # Solve the problem
                result = solve(numbers)
                print(f"\nCalculated longest subsequence length: {result}")

                # Send the answer back using sendline (adds newline automatically)
                p.sendline(str(result))
                print(f"Sent answer: {result}")
                break # Exit the loop after solving the first challenge
        
        # Keep the connection open to receive the flag
        print("\n--- Final server response (flag) ---")
        p.interactive()

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
