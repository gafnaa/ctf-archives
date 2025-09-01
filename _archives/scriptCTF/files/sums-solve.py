#!/usr/bin/env python3
from pwn import *

# --- Configuration ---
# Set the host and port to connect to.
HOST = 'play.scriptsorcerers.xyz'
PORT = 10180

def solve():
    """
    Connects to the server, solves the range sum queries, and gets the flag.
    """
    # Establish a connection to the remote server.
    # The 'context.log_level' can be set to 'debug' for more verbose output.
    context.log_level = 'info'
    conn = remote(HOST, PORT)

    try:
        # --- Stage 1: Receive Numbers ---
        # The server first sends a single line containing all the numbers.
        log.info("Receiving the list of numbers...")
        # Read the line, strip whitespace, split by spaces, and convert to integers.
        nums_line = conn.recvline().strip()
        nums = [int(x) for x in nums_line.split()]
        n = len(nums)
        log.success(f"Successfully received {n} numbers.")

        # --- Stage 2: Receive Ranges ---
        # The server then sends 'n' lines, each with a start and end for a range query.
        log.info("Receiving the range queries...")
        ranges = []
        for i in range(n):
            range_line = conn.recvline().strip()
            l, r = map(int, range_line.split())
            ranges.append((l, r))
        log.success(f"Successfully received {n} range queries.")

        # --- Stage 3: Calculate Prefix Sums ---
        # To answer the queries quickly, we pre-calculate the prefix sums.
        # The prefix sum at index i is the sum of all numbers from the start up to i.
        # This allows us to find the sum of any range [l, r] in O(1) time.
        log.info("Calculating prefix sums for efficient querying...")
        prefix_sums = [0] * (n + 1)
        for i in range(n):
            prefix_sums[i+1] = prefix_sums[i] + nums[i]
        log.success("Prefix sums calculation complete.")

        # --- Stage 4: Answer Queries ---
        # Now, we iterate through each query and send the answer back.
        log.info("Calculating and sending answers for each query...")
        for l, r in ranges:
            # The sum of the inclusive range [l, r] is calculated by:
            # (sum up to r) - (sum up to l-1)
            # which corresponds to prefix_sums[r+1] - prefix_sums[l].
            range_sum = prefix_sums[r+1] - prefix_sums[l]
            
            # Send the calculated sum back to the server as a string followed by a newline.
            conn.sendline(str(range_sum))
        
        log.success("All answers have been sent.")

        # --- Stage 5: Receive the Flag ---
        # If all answers are correct and sent within the time limit,
        # the server will respond with the flag.
        log.info("Waiting for the flag...")
        
        # Print all remaining output from the server.
        response = conn.recvall(timeout=2)
        print(response.decode(errors='ignore'))

    except Exception as e:
        log.error(f"An error occurred: {e}")
    finally:
        # Always close the connection.
        conn.close()
        log.info("Connection closed.")

if __name__ == "__main__":
    solve()
