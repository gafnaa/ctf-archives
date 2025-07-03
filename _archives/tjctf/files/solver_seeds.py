import time
import datetime
import ast
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from pwn import *

class RandomGenerator:
    def __init__(self, seed = None, modulus = 2 ** 32, multiplier = 157, increment = 1):
        if seed is None: 
            seed = time.asctime()
        if type(seed) is int: 
            self.seed = seed
        if type(seed) is str: 
            self.seed = int.from_bytes(seed.encode(), "big")
        if type(seed) is bytes: 
            self.seed = int.from_bytes(seed, "big")
        self.m = modulus
        self.a = multiplier
        self.c = increment

    def randint(self, bits: int):
        self.seed = (self.a * self.seed + self.c) % self.m
        result = self.seed.to_bytes(4, "big")
        while len(result) < bits // 8:
            self.seed = (self.a * self.seed + self.c) % self.m
            result += self.seed.to_bytes(4, "big")
        return int.from_bytes(result, "big") % (2 ** bits)

    def randbytes(self, len: int):
        return self.randint(len * 8).to_bytes(len, "big")

def solve():
    HOST = 'tjc.tf'
    PORT = 31493

    r = remote(HOST, PORT)

    # Receive the initial ciphertext
    r.recvuntil(b"ciphertext = ")
    ciphertext_line = r.recvline().strip()
    log.debug(f"Raw ciphertext line: {ciphertext_line}")

    # The line is like: b"ciphertext = b'\\xXX\\xYY...'"
    # Use ast.literal_eval to safely parse the byte string
    # We need to extract the part after "ciphertext = "
    # Find the index of b"b'" to get the actual byte string representation
    start_index = ciphertext_line.find(b"b'")
    if start_index == -1:
        log.error("Could not find the start of the byte string in ciphertext line.")
        r.close()
        return
    
    ciphertext_repr_bytes = ciphertext_line[start_index:]
    ciphertext = ast.literal_eval(ciphertext_repr_bytes.decode())

    log.info(f"Received ciphertext: {ciphertext.hex()}")

    # Define a time window to search for the seed
    # Current time is 6/7/2025, 12:00:50 PM (Asia/Jakarta, UTC+7:00)
    # Let's search +/- 5 minutes around this time.
    # The server is likely running in UTC or a similar timezone.
    # time.asctime() uses local time, but the server's local time might be different.
    # It's safer to assume UTC for the server and adjust our local time.
    
    # Let's try to get the current time in UTC and then adjust for a window
    now_utc = datetime.datetime.utcnow()
    
    # Search window: +/- 10 minutes (600 seconds)
    for i in range(-600, 600):
        test_time = now_utc + datetime.timedelta(seconds=i)
        # Format the time to match time.asctime() output
        # Example: 'Fri Jun  7 12:00:50 2025'
        # time.asctime() expects a time.struct_time object or no argument for current time.
        # We need to convert datetime object to struct_time for time.asctime() to format it correctly.
        seed_str = time.asctime(test_time.timetuple()).encode()
        
        randgen = RandomGenerator(seed=seed_str)
        
        # Generate the first key (used for flag encryption)
        key = randgen.randbytes(32)

        try:
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted_flag = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
            if b"tjctf{" in decrypted_flag:
                log.success(f"Found flag: {decrypted_flag.decode()}")
                r.close()
                return

        except ValueError:
            # Padding error, likely wrong key
            continue
        except Exception as e:
            # Other errors
            log.debug(f"Error with seed {asctime_str}: {e}")
            continue
    
    log.failure("Flag not found within the search window.")
    r.close()

if __name__ == "__main__":
    solve()
