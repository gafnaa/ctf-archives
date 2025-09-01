import socket
import binascii
import sys
from tqdm import tqdm

# --- Configuration ---
# Server details from the problem description
HOST = "23.146.248.136"
PORT = 9999
BLOCK_SIZE = 16  # AES block size is 16 bytes

# Ciphertext from out.txt
CIPHERTEXT_HEX = "1dbef3236e74e1bf9e7238102f5c4f9a1ac669f8a3bc5ea6f903085b4429e66f3089a928e64ac26b9f6e3c800c55d833"

class Oracle:
    """A helper class to manage the connection to the padding oracle."""
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self._connect()

    def _connect(self):
        """Establishes a connection to the server."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.sock.recv(1024)  # Consume the welcome message
        except socket.error as e:
            print(f"Failed to connect to {self.host}:{self.port}. Error: {e}")
            sys.exit(1)

    def query(self, payload_bytes):
        """Sends a payload to the oracle and returns True if padding is valid."""
        try:
            payload_hex = binascii.hexlify(payload_bytes)
            self.sock.sendall(payload_hex + b"\n")
            response = self.sock.recv(1024)
            return b"Valid" in response
        except (ConnectionResetError, BrokenPipeError):
            print("\nConnection lost. Reconnecting...")
            self._connect()
            return self.query(payload_bytes) # Retry the query

    def close(self):
        """Closes the socket connection."""
        self.sock.close()

def decrypt_block(oracle, prev_block, current_block):
    """
    Decrypts a single block of ciphertext using the padding oracle attack.
    
    Args:
        oracle (Oracle): The oracle instance to query.
        prev_block (bytes): The previous ciphertext block (or IV).
        current_block (bytes): The ciphertext block to decrypt.
        
    Returns:
        bytes: The decrypted plaintext block.
    """
    intermediate_state = bytearray(BLOCK_SIZE)

    # We attack the block from the last byte to the first
    for byte_index in range(BLOCK_SIZE - 1, -1, -1):
        padding_val = BLOCK_SIZE - byte_index
        crafted_iv = bytearray(b'\x00' * BLOCK_SIZE)

        # Set the bytes we already found to produce the correct padding value (e.g., 0x02, 0x02)
        for i in range(byte_index + 1, BLOCK_SIZE):
            crafted_iv[i] = intermediate_state[i] ^ padding_val

        found_guess = False
        # Create a progress bar for the byte guessing process
        pbar = tqdm(range(256), desc=f"Finding byte {15-byte_index}", leave=False, unit="guess")
        for guess in pbar:
            crafted_iv[byte_index] = guess
            payload = bytes(crafted_iv) + current_block

            if oracle.query(payload):
                # We found the correct guess for the crafted IV byte!
                # I[n] = C'[n-1] XOR P'[n]
                # P'[n] is our padding value, C'[n-1] is our guess
                intermediate_byte = guess ^ padding_val
                intermediate_state[byte_index] = intermediate_byte
                found_guess = True
                pbar.close()
                break
        
        if not found_guess:
            pbar.close()
            raise Exception(f"Attack failed: Could not find a valid guess for byte {byte_index}")

    # P[n] = I[n] XOR C[n-1]
    plaintext_block = bytes([p_byte ^ i_byte for p_byte, i_byte in zip(prev_block, intermediate_state)])
    return plaintext_block

def pkcs7_unpad(data):
    """Removes PKCS#7 padding from a byte string."""
    if not data:
        return b""
    pad_len = data[-1]
    if pad_len > len(data) or data[-pad_len:] != bytes([pad_len] * pad_len):
        print("\nWarning: Final block does not have valid PKCS7 padding. Returning padded data.")
        return data
    return data[:-pad_len]

def main():
    """Main function to orchestrate the decryption."""
    print(f"🎯 Attacking server at {HOST}:{PORT}")
    ciphertext = binascii.unhexlify(CIPHERTEXT_HEX)

    # Split ciphertext into IV and subsequent blocks
    iv = ciphertext[:BLOCK_SIZE]
    ct_blocks = [ciphertext[i:i+BLOCK_SIZE] for i in range(BLOCK_SIZE, len(ciphertext), BLOCK_SIZE)]

    print(f"Ciphertext has {len(ct_blocks)} block(s) to decrypt.\n")
    
    oracle = Oracle(HOST, PORT)
    full_plaintext = b""
    prev_block = iv

    for i, block in enumerate(ct_blocks):
        print(f"--- Decrypting Block {i+1}/{len(ct_blocks)} ---")
        decrypted_block = decrypt_block(oracle, prev_block, block)
        print(f"✅ Plaintext Block {i+1}: {repr(decrypted_block)}")
        full_plaintext += decrypted_block
        prev_block = block # The current ciphertext block becomes the "IV" for the next one
        
    oracle.close()
    
    unpadded_plaintext = pkcs7_unpad(full_plaintext)

    print("\n" + "="*50)
    print("✨ Decryption Complete! ✨")
    print(f"Padded Plaintext (hex):   {full_plaintext.hex()}")
    try:
        print(f"Decrypted Message:        {unpadded_plaintext.decode()}")
    except UnicodeDecodeError:
        print(f"Decrypted Message (repr): {repr(unpadded_plaintext)}")
    print("="*50)


if __name__ == "__main__":
    main()