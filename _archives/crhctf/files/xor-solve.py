
# brute_xor_find_flag.py
# Strategies:
#  - single-byte XOR brute force
#  - derive repeating-key XOR by assuming "CRHC{" appears somewhere (keylen 1..12)

from itertools import cycle
import string

ct_hex = "3b623a0a0f316f16791a0c6f1927440f6f0521340c6f113b0d080742161d0b6f4316174c5e2d791a14492d2a06016f462c4c4d020f"
ct = bytes.fromhex(ct_hex)
flag_tag = "CRHC{"

def is_mostly_printable(s, threshold=0.95):
    printable = set(bytes(string.printable, 'ascii'))
    count = sum(1 for b in s if b in printable)
    return (count / len(s)) >= threshold

def single_byte_xor_bruteforce(ct):
    results = []
    for k in range(256):
        pt = bytes([b ^ k for b in ct])
        try:
            text = pt.decode('utf-8')
        except UnicodeDecodeError:
            continue
        if flag_tag in text:
            results.append((bytes([k]), text))
        elif is_mostly_printable(pt):
            # include printable candidates for inspection
            results.append((bytes([k]), text))
    return results

def derive_repeating_key_by_flag_assumption(ct, keylen_max=12):
    results = []
    n = len(ct)
    flaglen = len(flag_tag)
    for keylen in range(1, keylen_max+1):
        for offset in range(0, n - flaglen + 1):
            # attempt to derive key bytes based on assuming "CRHC{" occurs at this offset
            key = [None] * keylen
            conflict = False
            for j, ch in enumerate(flag_tag):
                pos = offset + j
                ki = pos % keylen
                derived_byte = ct[pos] ^ ord(ch)
                if key[ki] is None:
                    key[ki] = derived_byte
                elif key[ki] != derived_byte:
                    conflict = True
                    break
            if conflict:
                continue
            # fill any remaining None bytes with 0x00 (we'll still test)
            filled_key = bytes(b if b is not None else 0 for b in key)
            # decrypt with repeating key
            pt = bytes([c ^ filled_key[i % keylen] for i, c in enumerate(ct)])
            try:
                text = pt.decode('utf-8')
            except UnicodeDecodeError:
                continue
            # require that the flag_tag is present and plaintext mostly printable
            if flag_tag in text and is_mostly_printable(pt):
                results.append((filled_key, keylen, offset, text))
    return results

# Run single-byte attack
single_results = single_byte_xor_bruteforce(ct)
print("=== Single-byte XOR candidates (showing those with flag or mostly-printable) ===")
for k, text in single_results:
    print(f"key=0x{k.hex()} -> {text}")

# Run repeating-key derivation using assumed flag placement
rep_results = derive_repeating_key_by_flag_assumption(ct, keylen_max=12)
print("\n=== Repeating-key derived candidates (assuming 'CRHC{' appears somewhere) ===")
for key, keylen, offset, text in rep_results:
    ascii_key = ''.join(chr(b) if 32 <= b < 127 else f"\\x{b:02x}" for b in key)
    print(f"keylen={keylen} key={key.hex()} ({ascii_key}) offset={offset} -> {text}")
