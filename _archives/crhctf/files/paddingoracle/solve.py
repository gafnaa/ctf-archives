#!/usr/bin/env python3
# solve.py -- CBC padding-oracle cracker with verification to avoid false positives

from pwn import remote, log, context
import binascii
import time
import sys
import random

context.log_level = 'info'

HOST = "23.146.248.136"
PORT = 9999
BLOCK_SIZE = 16

# Provided ciphertext (IV || C1 || C2)
CT_HEX = "1dbef3236e74e1bf9e7238102f5c4f9a1ac669f8a3bc5ea6f903085b4429e66f3089a928e64ac26b9f6e3c800c55d833"
CT = binascii.unhexlify(CT_HEX)

def recv_banner(r):
    # read until the prompt that asks for ciphertext, with a safety timeout
    try:
        # server greets then says "Send ciphertext hex and press enter."
        data = r.recvuntil(b"Send ciphertext", timeout=2)
        # consume rest of the line
        try:
            r.recvline(timeout=0.2)
        except Exception:
            pass
        return data
    except Exception:
        # fallback: read whatever available
        try:
            return r.recvline(timeout=0.5)
        except Exception:
            return b""

def oracle_once(test_ct):
    """
    Send one ciphertext to the oracle and return True if server says "Valid padding".
    Returns None on transient error.
    """
    try:
        r = remote(HOST, PORT, timeout=3)
    except Exception as e:
        return None

    try:
        recv_banner(r)
        hex_ct = binascii.hexlify(test_ct)
        r.sendline(hex_ct)
        # server responds with either "Valid padding" or "Invalid padding"
        line = r.recvline(timeout=3)
        r.close()
        if not line:
            return None
        return b"Valid padding" in line
    except Exception:
        try:
            r.close()
        except Exception:
            pass
        return None

def oracle(test_ct, max_retries=3):
    """
    Robust oracle wrapper: retry a few times if connection problems occur.
    """
    for _ in range(max_retries):
        res = oracle_once(test_ct)
        if res is None:
            # transient failure -> small sleep and retry
            time.sleep(0.1)
            continue
        return res
    # final attempt
    return oracle_once(test_ct)

def verify_padding(prev_block, cur_block, intermediate_guess, pad_len):
    """
    Extra verification to avoid false positives:
    After we found a guess that produced Valid, we flip some other byte
    (outside the pad region) in the preceding block and confirm padding becomes invalid.
    If it remains valid, it was likely a lucky collision.
    """
    # construct prefix with modifications:
    attacker = bytearray(prev_block)
    # apply known intermediate bytes to make last pad_len bytes equal to pad_len
    for i in range(1, pad_len+1):
        attacker[-i] = intermediate_guess[-i] ^ pad_len

    # Now flip a random byte outside the padding area to test if validity was due to lucky plaintext
    flip_index = random.choice([i for i in range(BLOCK_SIZE - pad_len)])
    attacker[flip_index] ^= 0x42  # flip a bit
    test_ct = bytes(attacker) + bytes(cur_block)
    res = oracle(test_ct, max_retries=2)
    # If flip made it invalid -> original valid is trustworthy. If still valid -> suspicious.
    return res is False

def decrypt_block(prev_block, cur_block):
    """
    Standard CBC padding-oracle attack to decrypt cur_block given prev_block.
    Returns plaintext block.
    """
    prev = bytearray(prev_block)
    cur = bytearray(cur_block)
    intermediate = [0] * BLOCK_SIZE
    recovered = [0] * BLOCK_SIZE

    # We'll work from last byte to first
    for pad_len in range(1, BLOCK_SIZE + 1):
        found = False
        byte_index = BLOCK_SIZE - pad_len

        # For each guess (0..255)
        for guess in range(256):
            # make a working copy of prev
            attack = bytearray(prev)

            # set bytes for already discovered intermediate values to match desired pad
            for i in range(1, pad_len):
                attack[-i] = intermediate[-i] ^ pad_len

            # modify target byte
            attack[byte_index] = (prev[byte_index] ^ guess ^ pad_len) & 0xFF

            test_ct = bytes(attack) + bytes(cur)
            res = oracle(test_ct)

            if res is None:
                # transient network problem: skip this guess (or retry)
                continue

            if res:
                # additional verification step to avoid false positives (very important for pad_len == 1)
                # Build a candidate intermediate array to pass to verifier
                candidate_inter = intermediate.copy()
                candidate_inter[byte_index] = guess ^ pad_len

                ok = verify_padding(prev, cur, candidate_inter, pad_len)
                if not ok:
                    # false positive — keep searching
                    continue

                # accept this guess
                intermediate[byte_index] = guess ^ pad_len
                recovered[byte_index] = intermediate[byte_index] ^ prev[byte_index]
                found = True
                log.info(f"Found byte {byte_index}: 0x{recovered[byte_index]:02x} (pad_len {pad_len})")
                break

        if not found:
            # If we didn't find a byte for this pad length, raise an error — something is off
            log.error(f"Failed to find byte for pad length {pad_len}. Aborting.")
            raise Exception("Byte not found; possible network issues or non-oracle behavior")

    return bytes(recovered)

def main():
    # split into 16-byte blocks
    blocks = [CT[i:i+BLOCK_SIZE] for i in range(0, len(CT), BLOCK_SIZE)]
    if len(blocks) < 2:
        print("Need at least one block and IV.")
        sys.exit(1)

    iv = blocks[0]
    plaintext_blocks = []

    # decrypt block by block: for block i (i>=1) use blocks[i-1] as prev
    for i in range(1, len(blocks)):
        prev = blocks[i-1]
        cur = blocks[i]
        log.info(f"Decrypting block {i}/{len(blocks)-1} ...")
        p = decrypt_block(prev, cur)
        plaintext_blocks.append(p)

    plaintext = b"".join(plaintext_blocks)
    # try to unpad safely
    try:
        pad_len = plaintext[-1]
        if 1 <= pad_len <= BLOCK_SIZE and all(plaintext[-i] == pad_len for i in range(1, pad_len+1)):
            plaintext = plaintext[:-pad_len]
        else:
            log.warn("Padding bytes in recovered plaintext look invalid; returning raw block output.")
    except Exception:
        pass

    print("Recovered plaintext (raw bytes):", plaintext)
    try:
        print("Recovered plaintext (utf-8):", plaintext.decode())
    except Exception:
        pass

if __name__ == "__main__":
    main()
