#!/usr/bin/env python3
"""
decryptor.py

General-purpose decryptor for binary blobs / PE files:
- Scans the file for likely ciphertext regions
- Tries single-byte XOR, repeating-key XOR (keylen up to 16),
  ROT-n (n=1..25), base64 decode, and (optional) AES-ECB/CBC
  if you supply keys.
- Scores outputs by English-likeness and prints top candidates.

Usage:
    python decryptor.py sample.bin
    python decryptor.py sample.bin --min-region 8 --max-region 512
    python decryptor.py sample.bin --aes-key 00112233445566778899aabbccddeeff --aes-mode ecb

Notes:
- For AES you need `pycryptodome` installed (pip install pycryptodome).
- The script tries to be conservative on output volume; increase --top if needed.
"""

import sys
import argparse
import math
import base64
from collections import Counter

# Optional AES
try:
    from Crypto.Cipher import AES
    HAVE_AES = True
except Exception:
    HAVE_AES = False

PRINTABLE = set(range(9, 14)) | set(range(32, 127))  # tabs/newline + normal prints

ENGLISH_FREQ = {
    'E': 12.0, 'T': 9.10, 'A': 8.12, 'O': 7.68, 'I': 7.31, 'N': 6.95,
    'S': 6.28, 'R': 6.02, 'H': 5.92, 'D': 4.32, 'L': 3.98, 'U': 2.88,
    'C': 2.71, 'M': 2.61, 'F': 2.30, 'Y': 2.11, 'W': 2.09, 'G': 2.03,
    'P': 1.82, 'B': 1.49, 'V': 1.11, 'K': 0.69, 'X': 0.17, 'Q': 0.11, 'J': 0.10, 'Z': 0.07
}

def load_file(path):
    with open(path, "rb") as f:
        return f.read()

def is_mostly_printable(bs, thresh=0.85):
    if not bs:
        return False
    good = sum(1 for b in bs if b in PRINTABLE)
    return (good / len(bs)) >= thresh

def english_score(text):
    # text: bytes or str assumed ascii
    if isinstance(text, bytes):
        try:
            text = text.decode('latin1')
        except Exception:
            return -999
    # letter frequency metric + penalize non-printables
    total = len(text)
    if total == 0:
        return -999
    nonprint = sum(1 for c in text if ord(c) not in PRINTABLE)
    if nonprint / total > 0.4:
        return -999
    cnt = Counter(c.upper() for c in text if c.isalpha())
    score = 0.0
    for ch, freq in ENGLISH_FREQ.items():
        score += abs(cnt.get(ch,0)/max(1,total) * 100 - freq) * -1.0
    # reward common digrams / spaces
    score += text.count(' ') * 0.5
    score += text.count(' the ') * 2.0
    return score

def chunks_from_data(data, min_len=8, max_len=512, step=1):
    n = len(data)
    for start in range(0, n, step):
        for length in (min_len, 16, 32, 64, 128, 256, 512):
            if length < min_len or length > max_len:
                continue
            if start + length <= n:
                yield start, data[start:start+length]
        # also yield a moving 32-window for finer search
        if start + 32 <= n:
            yield start, data[start:start+32]

def try_single_byte_xor(block):
    candidates = []
    for k in range(256):
        dec = bytes([b ^ k for b in block])
        if not is_mostly_printable(dec, thresh=0.5):
            continue
        score = english_score(dec)
        candidates.append((score, k, dec))
    candidates.sort(reverse=True, key=lambda t: t[0])
    return candidates[:6]

def try_repeating_xor(block, max_keylen=16):
    candidates = []
    for keylen in range(2, max_keylen+1):
        key = bytearray(keylen)
        # derive key by frequency for each position
        for i in range(keylen):
            column = block[i::keylen]
            # try single-byte best for this column (frequency on spaces / letters)
            best_k = 0
            best_score = -1e9
            for k in range(256):
                dec = bytes([b ^ k for b in column])
                # score: space frequency + printable fraction
                sp = dec.count(0x20)
                printable_frac = sum(1 for b in dec if b in PRINTABLE) / max(1, len(dec))
                s = sp * 2 + printable_frac * 5
                if s > best_score:
                    best_score = s
                    best_k = k
            key[i] = best_k
        dec_all = bytes([b ^ key[i % keylen] for i, b in enumerate(block)])
        if not is_mostly_printable(dec_all, thresh=0.4):
            continue
        score = english_score(dec_all)
        candidates.append((score, bytes(key), dec_all))
    candidates.sort(reverse=True, key=lambda t: t[0])
    return candidates[:6]

def try_rot(block):
    candidates = []
    try:
        s = block.decode('latin1')
    except Exception:
        return []
    for r in range(1,26):
        trans = []
        for ch in s:
            if 'a' <= ch <= 'z':
                trans.append(chr((ord(ch)-97+r) % 26 + 97))
            elif 'A' <= ch <= 'Z':
                trans.append(chr((ord(ch)-65+r) % 26 + 65))
            else:
                trans.append(ch)
        txt = ''.join(trans)
        if is_mostly_printable(txt.encode('latin1'), thresh=0.85):
            candidates.append((english_score(txt), r, txt))
    candidates.sort(reverse=True, key=lambda t: t[0])
    return candidates[:4]

def try_base64(block):
    try:
        s = block.decode('ascii', errors='ignore').strip()
    except Exception:
        return []
    s = ''.join(s.split())
    # quick base64 valid chars check
    if len(s) < 8:
        return []
    valid_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r")
    if any(c not in valid_chars for c in s[:64]):
        return []
    try:
        dec = base64.b64decode(s, validate=True)
        if is_mostly_printable(dec, thresh=0.5):
            return [(english_score(dec), dec)]
    except Exception:
        pass
    return []

def try_aes_variants(block, keys_hex, mode='ecb'):
    results = []
    if not HAVE_AES:
        return results
    for kh in keys_hex:
        try:
            key = bytes.fromhex(kh)
        except Exception:
            continue
        if len(key) not in (16, 24, 32):
            continue
        if mode.lower() == 'ecb':
            cipher = AES.new(key, AES.MODE_ECB)
            # try all aligned 16-byte offsets in the block
            for off in range(0, max(1, len(block)-16+1), 1):
                chunk = block[off:off + (len(block)//16)*16]
                if len(chunk) < 16:
                    continue
                try:
                    dec = cipher.decrypt(chunk)
                except Exception:
                    continue
                if is_mostly_printable(dec[:128], thresh=0.5):
                    results.append((english_score(dec[:512]), kh, off, dec))
        elif mode.lower() == 'cbc':
            # must provide IV or try zero IV
            iv = bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            for off in range(0, max(1, len(block)-16+1), 1):
                chunk = block[off:off + (len(block)//16)*16]
                if len(chunk) < 16:
                    continue
                try:
                    dec = cipher.decrypt(chunk)
                except Exception:
                    continue
                if is_mostly_printable(dec[:128], thresh=0.5):
                    results.append((english_score(dec[:512]), kh, off, dec))
    results.sort(reverse=True, key=lambda t: t[0])
    return results[:6]

def scan_file(data, args):
    results = []
    seen_offsets = set()
    for start, block in chunks_from_data(data, min_len=args.min_region, max_len=args.max_region, step=args.step):
        # skip duplicates / overlapping in a naive way
        if start in seen_offsets:
            continue
        seen_offsets.add(start)
        # quick entropy filter: look for not pure ASCII (so not trivial text)
        # but we still try on everything
        # Single-byte XOR
        sb = try_single_byte_xor(block)
        for score, key, dec in sb:
            if score > args.min_score:
                results.append(('single-xor', start, len(block), score, {'key': key, 'plaintext': dec}))
        # repeating-key XOR
        rk = try_repeating_xor(block, max_keylen=args.max_keylen)
        for score, key, dec in rk:
            if score > args.min_score:
                results.append(('repxor', start, len(block), score, {'key': key, 'plaintext': dec}))
        # ROT
        rt = try_rot(block)
        for score, r, dec in rt:
            if score > args.min_score:
                results.append(('rot', start, len(block), score, {'rot': r, 'plaintext': dec}))
        # base64
        b64 = try_base64(block)
        for score, dec in b64:
            if score > args.min_score:
                results.append(('base64', start, len(block), score, {'plaintext': dec}))
        # AES variants
        if args.aes_keys:
            aesr = try_aes_variants(block, args.aes_keys, mode=args.aes_mode)
            for score, kh, off, dec in aesr:
                if score > args.min_score:
                    results.append(('aes-'+args.aes_mode, start+off, len(dec), score, {'keyhex': kh, 'plaintext': dec}))
    results.sort(reverse=True, key=lambda t: t[3])
    return results[:args.top]

def pretty_print_results(results, out_limit=512):
    if not results:
        print("[no high-scoring candidates found]")
        return
    for typ, offset, length, score, meta in results:
        print("="*60)
        print(f"Type: {typ} | Offset: {offset} | Length: {length} | Score: {score:.2f}")
        if 'key' in meta:
            print("Key (raw):", meta['key'])
            try:
                print("Key (hex):", meta['key'].hex())
            except Exception:
                pass
        if 'keyhex' in meta:
            print("Key (hex):", meta['keyhex'])
        if 'rot' in meta:
            print("ROT: ", meta['rot'])
        pt = meta.get('plaintext', b'')
        if isinstance(pt, bytes):
            # try to decode as utf-8, fall back to latin1
            try:
                s = pt.decode('utf-8')
            except Exception:
                s = pt.decode('latin1', errors='replace')
        else:
            s = str(pt)
        print("--- plaintext (first %d bytes) ---" % out_limit)
        print(s[:out_limit])
        print()

def parse_args():
    p = argparse.ArgumentParser(description="Generic decryptor for binaries")
    p.add_argument("file", help="input file")
    p.add_argument("--min-region", type=int, default=8, help="minimum region size to try")
    p.add_argument("--max-region", type=int, default=256, help="maximum region size to try")
    p.add_argument("--step", type=int, default=8, help="step size (sliding window stride)")
    p.add_argument("--max-keylen", type=int, default=12, help="max keylen for repeating xor")
    p.add_argument("--min-score", type=float, default=-50.0, help="minimum english score to show")
    p.add_argument("--top", type=int, default=12, help="top results to show")
    p.add_argument("--aes-key", dest='aes_keys', action='append', default=[], help="AES key (hex). Can pass multiple times.")
    p.add_argument("--aes-mode", default='ecb', choices=['ecb','cbc'], help="AES mode to try if aes-key provided")
    return p.parse_args()

def main():
    args = parse_args()
    data = load_file(args.file)
    if args.aes_keys and not HAVE_AES:
        print("[warning] AES keys supplied but Crypto.Cipher.AES not available. Install pycryptodome for AES support.")
    results = scan_file(data, args)
    pretty_print_results(results)

if __name__ == "__main__":
    main()
