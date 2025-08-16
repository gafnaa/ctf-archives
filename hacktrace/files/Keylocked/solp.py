import sys, struct, os
from pathlib import Path
import math

if len(sys.argv) < 2:
    print("Usage: python3 solve_keylocked.py /path/to/keylocked.exe")
    sys.exit(1)

path = Path(sys.argv[1])
data = path.read_bytes()
n = len(data)
print(f"Read {n} bytes from {path}")

# Helper: find offsets of ASCII markers
def find_all(marker: bytes):
    off = 0
    res = []
    while True:
        i = data.find(marker, off)
        if i == -1:
            break
        res.append(i)
        off = i + 1
    return res

markers = [b'flag.enc', b'READ_ME_NOW.txt', b'All your important', b'scavengepoll', b'GetProcessTimes']
for m in markers:
    offs = find_all(m)
    if offs:
        print(f"Found marker {m!r} at offsets: {offs[:10]}")
    else:
        print(f"Marker {m!r} not found")

# Generic scanner for little-endian uint32 runs
def find_uint32_runs(max_val=20000, min_len=60):
    runs = []
    i = 0
    while i + 4 <= n:
        # skip obvious data-dense areas to accelerate: check next 4 bytes
        count = 0
        j = i
        while j + 4 <= n:
            v = struct.unpack_from('<I', data, j)[0]
            # allow small/frequent values and also some zeros
            if v <= max_val:
                count += 1
                j += 4
            else:
                break
        if count >= min_len:
            runs.append((i, count))
            i = j
        else:
            i += 1
    return runs

# Generic scanner for little-endian uint16 runs
def find_uint16_runs(max_val=20000, min_len=200):
    runs = []
    i = 0
    while i + 2 <= n:
        count = 0
        j = i
        while j + 2 <= n:
            v = struct.unpack_from('<H', data, j)[0]
            if v <= max_val:
                count += 1
                j += 2
            else:
                break
        if count >= min_len:
            runs.append((i, count))
            i = j
        else:
            i += 1
    return runs

# Restrict scanning length so it runs on typical machines in reasonable time
print("Scanning for uint32 runs (this may take a moment)...")
u32_runs = find_uint32_runs(max_val=20000, min_len=60)
print(f"Found {len(u32_runs)} uint32-run candidates (showing first 12):")
for off,cnt in u32_runs[:12]:
    # show first few values for quick glance
    vals = [struct.unpack_from('<I', data, off + 4*i)[0] for i in range(min(8, cnt))]
    print(f"  offset={off} count={cnt} first8={vals}")

print("Scanning for some candidate binary buffer regions (coarse sampling)...")
buffers = []
WINDOW = 65536
# sample buffer regions every 4096 bytes and keep those with many non-print bytes
for b in range(0, n, 4096):
    seg = data[b:b+WINDOW]
    if len(seg) < 256:
        continue
    nonprint = sum(1 for x in seg if x < 32 or x > 126)
    if nonprint > len(seg) * 0.6:
        buffers.append((b, len(seg)))
print(f"Coarse candidate buffers found: {len(buffers)} (showing up to 12): {buffers[:12]}")

def try_apply_indices_uint32(off, count, buf_bytes):
    indices = [struct.unpack_from('<I', data, off + 4*i)[0] for i in range(count)]
    # quick sanity: all indices must fit in buf
    if max(indices) >= len(buf_bytes):
        return None
    out = bytearray(len(indices))
    for i, idx in enumerate(indices):
        out[i] = buf_bytes[idx]
    return bytes(out)

def try_apply_indices_uint16(off, count, buf_bytes):
    indices = [struct.unpack_from('<H', data, off + 2*i)[0] for i in range(count)]
    if max(indices) >= len(buf_bytes):
        return None
    out = bytearray(len(indices))
    for i, idx in enumerate(indices):
        out[i] = buf_bytes[idx]
    return bytes(out)

# keywords to look for in candidate outputs (lowercase)
keywords = [b'flag', b'ctf', b'{', b'HTB', b'FLAG', b'CTF', b'flag{', b'GCTF']

candidates_found = []

# Try uint32 runs applied to coarse buffers
for off,count in u32_runs[:200]:  # limit attempts to first 200 candidate runs to keep fast
    for (b_off, b_len) in buffers[:40]:  # limit
        buf = data[b_off:b_off+WINDOW]
        if max(struct.unpack_from('<I', data, off+4*i)[0] for i in range(min(8, count))) >= len(buf):
            continue
        out = try_apply_indices_uint32(off, count, buf)
        if out is None: 
            continue
        low = out.lower()
        if any(k in low for k in keywords):
            print(f"\n=== Candidate match: uint32 idx_off={off} count={count} buf_off={b_off} ===")
            print(out[:500])
            candidates_found.append(('u32', off, count, b_off, out))
            # save preview
            Path(f"candidate_u32_{off}_{b_off}.bin").write_bytes(out)
            # break early if we found something
            #commented out break so we try to find multiple
        # else: occasionally print short ascii preview for debugging
        # if i%500==0: print(".", end="", flush=True)

# Try uint16 runs (many more candidates) but still limited
print("Scanning uint16 runs (limited) ...")
u16_runs = find_uint16_runs(max_val=20000, min_len=200)
print(f"Found {len(u16_runs)} uint16-run candidates (we'll test first 120)")
for off,count in u16_runs[:120]:
    for (b_off,b_len) in buffers[:40]:
        buf = data[b_off:b_off+WINDOW]
        # quick bounds check using first few indices
        sample_indices = [struct.unpack_from('<H', data, off + 2*i)[0] for i in range(min(12,count))]
        if max(sample_indices) >= len(buf):
            continue
        out = try_apply_indices_uint16(off, count, buf)
        if out is None:
            continue
        low = out.lower()
        if any(k in low for k in keywords):
            print(f"\n=== Candidate match: uint16 idx_off={off} count={count} buf_off={b_off} ===")
            print(out[:500])
            candidates_found.append(('u16', off, count, b_off, out))
            Path(f"candidate_u16_{off}_{b_off}.bin").write_bytes(out)

if not candidates_found:
    print("\nNo clear printable candidate found by heuristics. Some next steps you can try:")
    print(" * Increase max lengths / search regions in the script.")
    print(" * Manually inspect offsets near markers printed at start (e.g. near 'flag.enc' offset).")
    print(" * If you can run the binary in a Windows VM, let it create the files and then read them.")
else:
    print(f"\nFound {len(candidates_found)} candidate(s). Files saved with prefixes candidate_* .")
    for t, off, cnt, boff, out in candidates_found:
        print(f" - type {t} idx_off={off} len={cnt} buf_off={boff} preview={out[:120]!r}")