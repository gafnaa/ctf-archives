import socket
import binascii

# --- Connection Details ---
HOST = "ctf.compfest.id"
PORT = 7103

# --- Known values ---
AES_BLOCK_SIZE = 16

def get_encrypted_flag(s):
    """Requests the encrypted flag from the server."""
    s.recvuntil(b'> ')
    s.send(b'3\n')
    # The server responds with the hex-encoded flag followed by a newline.
    # We read that line and strip any whitespace.
    encrypted_flag_hex = s.recvuntil(b'\n').strip()
    return binascii.unhexlify(encrypted_flag_hex)

def decrypt_ciphertext(s, ct_hex):
    """Sends a ciphertext to the server for decryption."""
    s.recvuntil(b'> ')
    s.send(b'2\n')
    s.recvuntil(b'> ')
    s.send(ct_hex + b'\n')
    response = s.recvuntil(b'\n').strip()
    # The server might return an error message if padding is incorrect
    if b"Oops" in response or b"Tidak bisa" in response:
        return None
    try:
        # The server returns the raw bytes, which might not be valid utf-8
        # We are interested in the raw decrypted bytes.
        return response
    except (UnicodeDecodeError, binascii.Error):
        return None


def main():
    """
    Main exploit function.
    This script performs a CBC bit-flipping attack.
    The goal is to modify the IV of an encrypted flag block by block
    to trick the server into decrypting it for us.
    """
    # Use pwntools for easier socket interaction if available
    try:
        from pwn import remote
        s = remote(HOST, PORT)
    except ImportError:
        print("pwntools not found, using basic socket. For a better experience, run: pip install pwntools")
        s_basic = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_basic.connect((HOST, PORT))
        # Add recv_until helper for basic socket
        def recv_until(delimiter):
            data = b""
            while not data.endswith(delimiter):
                data += s_basic.recv(1)
            return data
        # Attach helper methods to the socket object to maintain a consistent API
        s_basic.recvuntil = recv_until
        s_basic.send = s_basic.sendall # Alias sendall to send for API consistency
        s = s_basic

    print(f"[*] Connected to {HOST}:{PORT}")

    # 1. Get the original encrypted flag
    encrypted_flag = get_encrypted_flag(s)
    print(f"[*] Got encrypted flag (hex): {binascii.hexlify(encrypted_flag).decode()}")

    iv_original = encrypted_flag[:AES_BLOCK_SIZE]
    ciphertext = encrypted_flag[AES_BLOCK_SIZE:]

    # Split ciphertext into blocks. The last block might be partial if reception was weird.
    ciphertext_blocks = [ciphertext[i:i + AES_BLOCK_SIZE] for i in range(0, len(ciphertext), AES_BLOCK_SIZE)]
    # We only process full blocks.
    full_ciphertext_blocks = [block for block in ciphertext_blocks if len(block) == AES_BLOCK_SIZE]
    
    # This list will hold the previous block for XORing (IV, then C1, C2, etc.)
    previous_xor_blocks = [iv_original] + full_ciphertext_blocks[:-1]
    
    full_plaintext = b""
    
    def recover_intermediate_block(target_ciphertext_block):
        intermediate_state = bytearray(AES_BLOCK_SIZE)
        for byte_index in range(AES_BLOCK_SIZE - 1, -1, -1):
            padding_byte = AES_BLOCK_SIZE - byte_index
            for guess in range(256):
                # Craft a malicious IV
                malicious_iv = bytearray(b'\x00' * AES_BLOCK_SIZE)
                
                # Set the suffix of the IV to create correct padding
                for i in range(byte_index + 1, AES_BLOCK_SIZE):
                    malicious_iv[i] = intermediate_state[i] ^ padding_byte
                
                # Set the current byte we are guessing
                malicious_iv[byte_index] = guess

                crafted_ct = bytes(malicious_iv) + target_ciphertext_block
                
                # Send to the server
                s.recvuntil(b'> ')
                s.send(b'2\n')
                s.recvuntil(b'> ')
                s.send(binascii.hexlify(crafted_ct) + b'\n')
                response = s.recvuntil(b'\n')

                if b"Oops" not in response and b"Tidak bisa" not in response:
                    # We found the correct byte!
                    intermediate_byte = guess ^ padding_byte
                    intermediate_state[byte_index] = intermediate_byte
                    print(f"\r[*] Found intermediate byte {AES_BLOCK_SIZE-byte_index}/{AES_BLOCK_SIZE}: {hex(intermediate_byte)}", end="")
                    break
            else:
                # This should not happen if the logic is correct
                print(f"\n[-] Could not find byte at index {byte_index}")
                return None
        print("\n[*] Intermediate block recovered.")
        return bytes(intermediate_state)

    # Loop through all full ciphertext blocks and decrypt them
    for i, block_to_decrypt in enumerate(full_ciphertext_blocks):
        print(f"[*] Recovering intermediate state for ciphertext block {i+1}/{len(full_ciphertext_blocks)}...")
        intermediate_state = recover_intermediate_block(block_to_decrypt)
        if not intermediate_state:
            print(f"[-] Failed to recover block {i+1}. Exiting.")
            s.close()
            return

        # Get the previous block to XOR with (IV for block 1, C1 for block 2, etc.)
        xor_block = previous_xor_blocks[i]
        
        # Calculate plaintext block: P_i = D(C_i) XOR C_{i-1}
        plaintext_block = bytes([xor_block[j] ^ intermediate_state[j] for j in range(AES_BLOCK_SIZE)])
        full_plaintext += plaintext_block

    # The final plaintext might have padding, which we can strip
    # The unpad function from Crypto.Util.Padding is the safest way
    try:
        from Crypto.Util.Padding import unpad
        flag = unpad(full_plaintext, AES_BLOCK_SIZE)
    except (ImportError, ValueError):
        # Fallback to simple rstrip if unpad fails or is not available
        flag = full_plaintext.rstrip(b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10')


    print("\n\n" + "="*50)
    print(f"[*] SUCCESS! Decrypted Flag: {flag.decode(errors='ignore')}")
    print("="*50 + "\n")

    s.close()


if __name__ == "__main__":
    main()
