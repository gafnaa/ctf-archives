#!/usr/bin/env python3
import pwn
import sys

HOST = "challs.watctf.org"
PORT = 2013  
BLOCK_SIZE = 16

def get_blocks(data: bytes) -> list[bytes]:
    """Splits binary data into a list of 16-byte blocks."""
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]

def solve_block(prev_block: bytes, target_block: bytes, oracle) -> bytes:
    pwn.log.info(f"Attacking block: {target_block.hex()}")
    
    intermediate_state = bytearray(BLOCK_SIZE)
    discovered_plaintext = bytearray(BLOCK_SIZE)

    for pad_val in range(1, BLOCK_SIZE + 1):
        byte_index = BLOCK_SIZE - pad_val
        pwn.log.info(f"Solving byte {byte_index} (padding value {pad_val})")

        forged_prev_block = bytearray(b'\x00' * BLOCK_SIZE)

        for i in range(pad_val - 1):
            idx = BLOCK_SIZE - 1 - i
            forged_prev_block[idx] = intermediate_state[idx] ^ pad_val
        
        found_byte = False
        # Brute-force the current byte we are trying to find
        for guess in range(256):
            forged_prev_block[byte_index] = guess
            
            # Construct the full ciphertext to send
            payload = forged_prev_block + target_block
            
            if oracle(payload):
                intermediate_state[byte_index] = guess ^ pad_val

                discovered_plaintext[byte_index] = intermediate_state[byte_index] ^ prev_block[byte_index]
                
                found_byte = True
                print(f"\r[+] Plaintext so far: {bytes(discovered_plaintext)}", end="", flush=True)
                break
        
        if not found_byte:
            raise Exception("Could not find a valid byte. Oracle might be inconsistent.")
    
    print() 
    pwn.log.success(f"Decrypted block: {discovered_plaintext.hex()} -> {discovered_plaintext.decode(errors='ignore')}")
    return bytes(discovered_plaintext)


def main():
    if len(sys.argv) > 2:
        global HOST, PORT
        HOST = sys.argv[1]
        PORT = int(sys.argv[2])

    p = pwn.remote(HOST, PORT)

    # Receive the original ciphertext
    original_ct_hex = p.recvline().strip().decode()
    pwn.log.info(f"Received original ciphertext: {original_ct_hex}")
    original_ct = bytes.fromhex(original_ct_hex)
    
    # The oracle function that interacts with the server
    def padding_oracle(payload: bytes) -> bool:
        p.sendlineafter(b"> ", payload.hex().encode())
        response = p.recvline().strip()
        return response == b"Valid padding"

    blocks = get_blocks(original_ct)
    iv = blocks[0]
    ct_blocks = blocks[1:]

    all_blocks = [iv] + ct_blocks
    
    full_plaintext = b""
    
    for i in range(1, len(all_blocks)):
        prev_c_block = all_blocks[i-1]
        target_c_block = all_blocks[i]
        
        pt_block = solve_block(prev_c_block, target_c_block, padding_oracle)
        full_plaintext += pt_block

    pwn.log.success(f"Full plaintext (with padding): {full_plaintext}")

    # Unpad the final result
    pad_len = full_plaintext[-1]
    unpadded_plaintext = full_plaintext[:-pad_len]

    pwn.log.success("--- FLAG ---")
    print(unpadded_plaintext.decode())
    
    p.close()


if __name__ == "__main__":
    main()
