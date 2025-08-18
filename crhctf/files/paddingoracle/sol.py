import socket
import binascii
from tqdm import tqdm

# --- Configuration ---
HOST = "23.146.248.136"
PORT = 9999
BLOCK_SIZE = 16
# Ciphertext from out.txt
CIPHERTEXT_HEX = "1dbef3236e74e1bf9e7238102f5c4f9a1ac669f8a3bc5ea6f903085b4429e66f3089a928e64ac26b9f6e3c800c55d833"
# --- End Configuration ---

def query_oracle(payload_hex: str) -> bool:
    """Sends a hex payload to the oracle and returns True for valid padding."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.recv(1024)  # Receive welcome message
        s.sendall(payload_hex.encode() + b'\n')
        response = s.recv(1024)
        return b"Valid" in response

def decrypt_block(prev_block: bytes, current_block: bytes) -> bytes:
    """Decrypts a single block using the padding oracle."""
    intermediate_state = bytearray(BLOCK_SIZE)
    padding_block = bytearray(BLOCK_SIZE) # This is our C'_{i-1}
    
    # Iterate backwards from the last byte to the first
    for pad_val in range(1, BLOCK_SIZE + 1):
        byte_index = BLOCK_SIZE - pad_val
        
        # Set the padding for bytes we've already found
        for i in range(byte_index + 1, BLOCK_SIZE):
            padding_block[i] = intermediate_state[i] ^ pad_val

        # Brute-force the current byte
        found = False
        for guess in range(256):
            padding_block[byte_index] = guess
            
            payload = padding_block + current_block
            payload_hex = binascii.hexlify(payload).decode()

            if query_oracle(payload_hex):
                # We found the correct guess!
                # intermediate_byte ^ guess = pad_val
                # so, intermediate_byte = guess ^ pad_val
                intermediate_byte = guess ^ pad_val
                intermediate_state[byte_index] = intermediate_byte
                found = True
                break
        
        if not found:
            raise Exception(f"Could not find valid byte for index {byte_index}")

    # Decrypt the plaintext using the found intermediate state
    # P[i] = I[i] ^ C[i-1]
    plaintext_block = bytes(a ^ b for a, b in zip(intermediate_state, prev_block))
    return plaintext_block


def main():
    """Main function to orchestrate the decryption."""
    print("Starting Padding Oracle Attack...")
    
    # Decode the full ciphertext and split it into blocks
    full_ciphertext = binascii.unhexlify(CIPHERTEXT_HEX)
    blocks = [full_ciphertext[i:i+BLOCK_SIZE] for i in range(0, len(full_ciphertext), BLOCK_SIZE)]
    
    # The first block is the IV, the rest are ciphertext blocks
    iv = blocks[0]
    ciphertext_blocks = blocks[1:]
    
    # We need to prepend the IV to the ciphertext blocks to have the C[i-1] for each C[i]
    # For C1, its C0 is the IV. For C2, its C1 is the first ciphertext block, etc.
    block_pairs = list(zip([iv] + ciphertext_blocks, ciphertext_blocks))
    
    full_plaintext = b''
    
    print(f"Found {len(ciphertext_blocks)} blocks to decrypt.")
    
    # Use tqdm for a progress bar
    for i, (prev_block, current_block) in enumerate(tqdm(block_pairs, desc="Decrypting Blocks")):
        plaintext_block = decrypt_block(prev_block, current_block)
        full_plaintext += plaintext_block

    print("\n\n--- Decryption Complete ---")
    
    # The final plaintext might have padding, so we unpad it manually
    pad_len = full_plaintext[-1]
    if pad_len > 0 and pad_len <= BLOCK_SIZE:
         # Check if padding is valid before stripping
        if all(b == pad_len for b in full_plaintext[-pad_len:]):
            unpadded_plaintext = full_plaintext[:-pad_len]
            print(f"Plaintext (unpadded): {unpadded_plaintext.decode('utf-8', errors='ignore')}")
            return

    print(f"Plaintext (raw): {full_plaintext.decode('utf-8', errors='ignore')}")


if __name__ == "__main__":
    main()