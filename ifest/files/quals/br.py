from Crypto.Util.number import inverse, long_to_bytes
from multiprocessing import Pool

# Load data
with open("out.txt") as f:
    c = int(f.readline())
    n = int(f.readline())
    low_p = int(f.readline())  # This is p >> 40

e = 0x10001

def try_upper_bits(upper_bits):
    # Reconstruct candidate p
    p_candidate = (upper_bits << 984) + low_p
    if n % p_candidate == 0:
        q = n // p_candidate
        phi = (p_candidate - 1) * (q - 1)
        d = inverse(e, phi)
        m = pow(c, d, n)
        try:
            flag = long_to_bytes(m)
            if b"IFEST13{" in flag:
                print(f"[+] Found: {flag}")
                return flag
        except:
            return None
    return None

# Use multiprocessing
if __name__ == '__main__':
    from tqdm import tqdm
    with Pool(20) as pool:
        for result in tqdm(pool.imap_unordered(try_upper_bits, range(2**40)), total=2**40):
            if result:
                print(result)
                break
