
# solver.py
# Reimplements transforms and checks from the decompiled binary.
# Uses known prefix "hacktoday{" and format "hacktoday{...}".
# Brute-forces only ambiguous positions and prints flags that verify.

from itertools import product

lookup_table = [
234,9,103,60,5,79,232,229,45,51,131,3,168,29,170,216,99,161,111,204,220,209,78,89,72,191,157,119,226,184,244,134,21,61,175,15,223,100,230,28,128,185,84,208,164,44,113,105,27,85,203,146,153,130,66,42,250,140,174,133,115,4,52,73,65,10,104,238,30,211,46,121,2,190,159,172,112,156,95,47,124,177,77,202,81,38,123,13,182,242,64,33,225,0,241,122,210,37,106,163,82,98,34,218,187,214,125,132,120,219,252,32,135,215,245,48,198,222,76,231,213,192,227,144,19,152,110,12,217,126,196,201,248,148,109,138,63,249,200,36,197,101,127,145,149,54,16,167,102,80,239,181,14,83,224,142,69,176,118,171,251,136,43,246,155,18,165,68,53,90,94,41,93,162,116,212,205,25,235,193,74,58,169,199,17,180,49,147,92,158,160,75,141,20,96,31,137,117,186,11,67,233,88,91,24,97,237,247,86,195,236,39,221,87,240,178,40,206,194,1,207,71,150,114,56,107,243,179,166,183,50,143,254,154,129,59,55,23,7,8,108,151,22,139,228,253,173,26,188,35,255,62,70,189,6,57
]

def u8(x): return x & 0xFF

def shift(a1, a2):
    return u8(((u8(a1) - 32 + ((5*a2 + 3) % 94)) % 94) + 32)

def rot13(a1):
    if a1 > 0x60 and a1 <= 0x7A:
        return u8(((a1 - 84) % 26) + 97)
    if a1 <= 0x40 or a1 > 0x5A:
        return u8(a1)
    return u8(((a1 - 52) % 26) + 65)

def rol(a1, a2):
    return u8(((a1 << a2) | (a1 >> (8 - a2))))

def keyxor(a1, a2):
    return u8(((7 * a2 + 11) % 256) ^ a1)

def lookup(a1):
    return lookup_table[a1]

def not_(a1):
    return u8(~a1)

def addpos(a1, a2):
    return u8((a1 + (a2 % 17)) % 256)

def swap_nibble(a1):
    return u8((16 * a1) | (a1 >> 4))

def xor_a5(a1):
    return u8(a1 ^ 0xA5)

def rol3(a1):
    return rol(a1, 3)

def xor3c(a1):
    return u8(a1 ^ 0x3C)

def rol1(a1):
    return rol(a1, 1)

def full_transform(a1, a2):
    v13 = shift(a1, a2)
    v12 = rot13(v13)
    v11 = rol(v12, a2 % 8)
    v10 = keyxor(v11, a2)
    v9  = lookup(v10)
    v8  = not_(v9)
    v7  = addpos(v8, a2)
    v6  = swap_nibble(v7)
    v5  = xor_a5(v6)
    v4  = rol3(v5)
    v3  = xor3c(v4)
    return rol1(v3)

def popcount8(x):
    return bin(u8(x)).count("1")

def checks_value(i, v):
    # mirror the f0..f85 checks. v is already an unsigned byte (0..255)
    # (compact mapping of the decompiled checks)
    if i == 0: return v == 1
    if i == 1: return u8(6 - v) == 104
    if i == 2: return v == 125
    if i == 3: return u8(2 * v - 10) == 252
    if i == 4: return u8((v & 0xF0) | (v >> 4)) == 102
    if i == 5: return u8((v ^ 0x3C) + 16) == 95
    if i == 6: return v == u8(-112)
    if i == 7: return u8((2 * v) ^ v) == 18
    if i == 8: return u8((2 * v) ^ 0x33) == 101
    if i == 9: return u8((v >> 2) + 85) == 135
    if i == 10: return v == u8(-24)
    if i == 11: return u8(2 - v) == 86
    if i == 12: return v == u8(-115)
    if i == 13: return u8((4 * v) ^ 0xA5) == 41
    if i == 14: return v == 110
    if i == 15: return u8(15 - v) == 17
    if i == 16: return v == 0
    if i == 17: return u8(3 * v - 7) == 46
    if i == 18: return (v >> 1) == 104
    if i == 19: return u8((2 * v) ^ v) == 249
    if i == 20: return u8((v + 34) ^ 0x77) == 17
    if i == 21: return v == 86
    if i == 22: return u8(3 * v + 1) == 43
    if i == 23: return v == u8(-78)
    if i == 24: return u8((v ^ 0x3C) - 34) == 189
    if i == 25: return u8(3 * v + 5) == 160
    if i == 26: return u8((v >> 2) + 51) == 79
    if i == 27: return u8(((2 * v) ^ v) + 7) == 121
    if i == 28: return u8(41 - (v ^ 0xB2)) == 212
    if i == 29: return u8((v - 90) ^ 0x5A) == 165
    if i == 30: return u8((v ^ 0x32) + 16) == 181
    if i == 31: return u8(31 - v) == 30
    if i == 32: return v == u8(-123)
    if i == 33: return v == u8(-58)
    if i == 34: return u8((v ^ 0x3C) - 34) == 210
    if i == 35: return u8(3 * v + 5) == 61
    if i == 36: return u8((v >> 2) + 51) == 77
    if i == 37: return u8(((2 * v) ^ v) + 7) == 109
    if i == 38: return u8(41 - (v ^ 0x48)) == 212
    if i == 39: return u8((v - 55) ^ 0x5A) == 165
    if i == 40: return u8((v ^ 0x87) + 16) == 181
    if i == 41: return u8(31 - v) == 159
    if i == 42: return v == u8(-106)
    if i == 43: return v == u8(-44)
    if i == 44: return v == 34
    if i == 45: return u8(v - 80) == 35
    if i == 46: return u8(2 * v) == 218
    if i == 47: return v == 75
    if i == 48: return (v >> 1) == 122
    if i == 49: return v == 9
    if i == 50: return v == 64
    if i == 51: return u8(2 * v) == 22
    if i == 52: return u8((2 * v) | (v >> 7)) == 0xEB
    if i == 53: return u8((16 * v) | (v >> 4)) == 39
    if i == 54: return u8(3 * v) == 0x97
    if i == 55: return u8(118 - v) == 7
    if i == 56: return u8((4 * v) ^ 0x49) == 221
    if i == 57: return v == u8(-47)
    if i == 58: return (v >> 1) == 61
    if i == 59: return v == 122
    if i == 60: return u8((5 * v) ^ 0x66) == 93
    if i == 61: return (v >> 3) == 31
    if i == 62: return v == u8(-63)
    if i == 63: return (v >> 1) == 120
    if i == 64: return u8(2 * (v ^ 0x31)) == 42
    if i == 65: return u8(40 - v) == 104
    if i == 66: return u8((2 * v) ^ 0x8F) == 133
    if i == 67: return u8((16 * v) | (v >> 4)) == 0x8D
    if i == 68: return u8((3 * v) ^ 0x2A) == 99
    if i == 69: return u8(((v >> 3) | ((v * 32) & 0xFF))) == 0xA0
    if i == 70: return u8(2 * (v ^ 0x55)) == 204
    if i == 71: return (v >> 2) == 61
    if i == 72: return u8(v + popcount8(v)) == 155
    if i == 73: return u8((v & 0xF0) | 7) == 103
    if i == 74: return u8((8 * v) ^ 0x33) == 195
    if i == 75:
        rev = 0
        for b in range(8):
            rev |= (((v >> b) & 1) << (7 - b))
        return rev == u8(-91)
    if i == 76: return (v >> 2) == 47
    if i == 77: return v == u8(-27)
    if i == 78: return u8((5 * v) ^ 0x64) == 90
    if i == 79: return u8((4 * v) | (v >> 6)) == 0xCA
    if i == 80: return u8(118 - v) == 183
    if i == 81: return u8((2 * v) ^ 0x29) == 159
    if i == 82: return u8(v + ((v >> 4) + (v & 0xF))) == 206
    if i == 83: return u8((7 * v) ^ 0x42) == 50
    if i == 84: return (v >> 1) == 36
    if i == 85: return (v & 0x1F) == 27
    return False

def verify_flag(s):
    if len(s) != 86: 
        return False
    for i in range(86):
        v2 = full_transform(ord(s[i]), i+1)
        if not checks_value(i, v2):
            return False
    return True

def find_candidates(known_prefix, known_suffix):
    candidates = []
    for pos in range(86):
        a2 = pos + 1
        # if fixed by known prefix/suffix, just use that
        if pos < len(known_prefix):
            candidates.append([known_prefix[pos]])
            continue
        if pos >= 86 - len(known_suffix):
            # suffix position
            suffix_pos = pos - (86 - len(known_suffix))
            candidates.append([known_suffix[suffix_pos]])
            continue

        found = []
        # try printable ascii range
        for ch in range(32, 127):
            ft = full_transform(ch, a2)
            if checks_value(pos, ft):
                found.append(chr(ch))
        # fallback to all bytes if none found (unlikely)
        if not found:
            for ch in range(256):
                ft = full_transform(ch, a2)
                if checks_value(pos, ft):
                    found.append(chr(ch) if 32 <= ch < 127 else f"\\x{ch:02x}")
        candidates.append(found)
    return candidates

def main():
    prefix = "hacktoday{"   # provided format
    suffix = "}"            # closing brace assumed at the end
    if len(prefix) >= 86:
        print("Provided prefix too long for 86-char flag.")
        return

    cands = find_candidates(prefix, suffix)
    # print candidate counts and early bail if something impossible
    total = 1
    ambiguous_positions = []
    for i, lst in enumerate(cands):
        print(f"pos {i} candidates: {len(lst)} -> {lst[:10]}")
        if len(lst) == 0:
            print("No candidates for position", i)
            return
        total *= len(lst)
        if len(lst) > 1:
            ambiguous_positions.append(i)

    print("Total combinations to try:", total)
    if total > 5_000_000:
        print("Combination space too large to brute-force here. Inspect candidates manually.")
        return

    # build index lists & candidate lists for ambiguous positions only
    amb_idxs = [i for i in range(86) if len(cands[i]) > 1]
    amb_lists = [cands[i] for i in amb_idxs]

    print("Ambiguous positions:", amb_idxs)
    solutions = []
    # iterate product across ambiguous positions and construct full strings
    for comb in product(*amb_lists):
        s_list = [''] * 86
        # fill with fixed or chosen values
        comb_map = dict(zip(amb_idxs, comb))
        for pos in range(86):
            if pos in comb_map:
                s_list[pos] = comb_map[pos]
            else:
                s_list[pos] = cands[pos][0]
        candidate_flag = ''.join(s_list)
        if verify_flag(candidate_flag):
            solutions.append(candidate_flag)
            print("Found valid flag:", candidate_flag)

    if not solutions:
        print("No valid flag found (unexpected).")
    else:
        print("\nAll solutions:")
        for sol in solutions:
            print(sol)

if __name__ == "__main__":
    main()
