
import subprocess
import sys

BINARY = "./Packs.exe"
WINE = False   # ubah True jika harus pake wine
CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}-!@#$%^&*()[]:;<>?,./\\|+ "
L = 48   # panjang flag hasil deteksi

def run_input(s):
    cmd = [BINARY]
    if WINE:
        cmd = ["wine", BINARY]
    try:
        p = subprocess.run(cmd, input=(s+"\n").encode(),
                           capture_output=True, timeout=4)
    except subprocess.TimeoutExpired:
        return None
    return p.stdout.decode(errors="ignore")

def count_nope(out):
    return out.count("Nope.")

filler = "A"
flag = list(filler * L)

for i in range(L):
    candidate_base = "".join(flag[:i]) + filler*(L-i)
    out_base = run_input(candidate_base)
    if out_base is None:
        print("Program timeout saat baseline.")
        sys.exit(1)
    base_nope = count_nope(out_base)

    print(f"\nTesting position {i+1}/{L} (baseline Nope={base_nope})")
    found = False
    for c in CHARS:
        candidate = "".join(flag[:i]) + c + filler*(L-i-1)
        out = run_input(candidate)
        if out is None:
            continue
        n = count_nope(out)
        if n < base_nope:
            print(f"Found char at pos {i} = {repr(c)} (Nope {n} < {base_nope})")
            flag[i] = c
            found = True
            break
    if not found:
        print("Bypassing pos", i, "- belum ketemu, isi filler dulu")
        # biarin flag[i] = 'A' (atau filler)
        continue
    print("Progress:", "".join(flag))


print("\nRecovered flag:", "".join(flag))