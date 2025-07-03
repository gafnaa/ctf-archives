import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256
import sys

# Configuration
HOST = "0.cloud.chals.io"
PORT = 26625
N_BYTES_NETWORK = 1024  # Byte length for network transmission of p, g, k_a, k_b

def recv_all(sock, n_bytes):
    """
    Helper function to receive exactly n_bytes from a socket.
    """
    data = bytearray()
    while len(data) < n_bytes:
        packet = sock.recv(n_bytes - len(data))
        if not packet:
            # Connection closed prematurely
            return None
        data.extend(packet)
    return bytes(data)

def solve():
    """
    Connects to the server, exploits the Diffie-Hellman implementation
    to force a predictable shared secret, and decrypts the flag.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            print(f"[*] Connected to {HOST}:{PORT}")

            # 1. Read p, g, k_a from the server
            # These are sent as N_BYTES_NETWORK-byte integers.
            print(f"[*] Receiving p ({N_BYTES_NETWORK} bytes)...")
            p_bytes = recv_all(s, N_BYTES_NETWORK)
            if p_bytes is None or len(p_bytes) != N_BYTES_NETWORK:
                print(f"[!] Error: Failed to receive complete p. Expected {N_BYTES_NETWORK} bytes, got {len(p_bytes) if p_bytes else 0}")
                return
            print(f"[*] Received p.")

            print(f"[*] Receiving g ({N_BYTES_NETWORK} bytes)...")
            g_bytes = recv_all(s, N_BYTES_NETWORK)
            if g_bytes is None or len(g_bytes) != N_BYTES_NETWORK:
                print(f"[!] Error: Failed to receive complete g. Expected {N_BYTES_NETWORK} bytes, got {len(g_bytes) if g_bytes else 0}")
                return
            print(f"[*] Received g.")
            
            print(f"[*] Receiving k_a ({N_BYTES_NETWORK} bytes)...")
            k_a_bytes = recv_all(s, N_BYTES_NETWORK)
            if k_a_bytes is None or len(k_a_bytes) != N_BYTES_NETWORK:
                print(f"[!] Error: Failed to receive complete k_a. Expected {N_BYTES_NETWORK} bytes, got {len(k_a_bytes) if k_a_bytes else 0}")
                return
            print(f"[*] Received k_a.")

            # 2. Construct and send our chosen k_b
            # We choose k_b_val = 1. This will make the shared secret k = 1.
            k_b_val = 1
            # Convert k_b_val to N_BYTES_NETWORK bytes, big-endian.
            # This will be b'\x00\x00...\x00\x01' (1023 zeros, then 1).
            k_b_to_send = k_b_val.to_bytes(N_BYTES_NETWORK, 'big')
            
            print(f"[*] Sending malicious k_b (value 1, as {N_BYTES_NETWORK} bytes)...")
            s.sendall(k_b_to_send)
            print(f"[*] Sent k_b.")

            # 3. Read the encrypted flag from the server
            # The server sends IV (16 bytes) + AES-CBC encrypted data.
            print(f"[*] Receiving encrypted flag data...")
            # Assuming the server sends all flag data then closes, or sends a fixed amount.
            # The previous log showed 4096 bytes were received.
            encrypted_flag_data = s.recv(4096) 
            if not encrypted_flag_data:
                print(f"[!] Error: No encrypted flag data received.")
                return
            print(f"[*] Received {len(encrypted_flag_data)} bytes of encrypted flag data.")

            # 4. Calculate the predictable shared secret 'k'
            shared_k_val = 1

            # 5. Prepare the shared secret for hashing as the server does:
            shared_k_bytes_for_hash = shared_k_val.to_bytes(1, 'big') # This will be b'\x01'
            print(f"[*] Predictable shared secret bytes for hashing: {shared_k_bytes_for_hash.hex()}")

            # 6. Derive the AES key using SHA256, as the server does
            aes_key = sha256(shared_k_bytes_for_hash).digest()
            print(f"[*] Derived AES key: {aes_key.hex()}")

            # 7. Extract IV and Ciphertext from the received data
            if len(encrypted_flag_data) < AES.block_size:
                print(f"[!] Error: Encrypted data is too short to contain an IV ({len(encrypted_flag_data)} bytes).")
                return
                
            iv = encrypted_flag_data[:AES.block_size]
            ciphertext = encrypted_flag_data[AES.block_size:]
            print(f"[*] IV: {iv.hex()}")

            if not ciphertext:
                print(f"[!] Error: Ciphertext is empty after extracting IV.")
                return
            
            if len(ciphertext) % AES.block_size != 0:
                print(f"[!] Warning: Ciphertext length ({len(ciphertext)}) is not a multiple of AES block size ({AES.block_size}). This will cause decryption to fail.")
                # Pycryptodome's AES decrypt requires the data length to be a multiple of the block size.
                # If this warning appears, it means the received encrypted_flag_data length is problematic.
                return


            # 8. Decrypt and unpad
            padded_data = b'' # Initialize to ensure it's defined for the except block
            try:
                cipher = AES.new(aes_key, AES.MODE_CBC, iv)
                padded_data = cipher.decrypt(ciphertext)
                data = unpad(padded_data, AES.block_size)
                flag = data.decode('utf-8', errors='replace') 
                print(f"\n[+] Successfully Decrypted Flag:\n{flag}")
            except ValueError as e:
                print(f"[!] Error during decryption or unpadding: {e}")
                print(f"[!] This might happen if the key is wrong, IV is wrong, data is corrupt, or padding is incorrect.")
                if isinstance(padded_data, bytes) and len(padded_data) > 0:
                    print(f"    Padded data (first 32 bytes if available): {padded_data[:32].hex() if len(padded_data) >=32 else padded_data.hex()}")
                    print(f"    Padded data (last 16 bytes if available): {padded_data[-16:].hex() if len(padded_data) >=16 else padded_data.hex()}")
                    if len(padded_data) > 0: # Redundant check, but safe
                        print(f"    Last byte of padded_data (value {padded_data[-1]}): {padded_data[-1:].hex()}")
                else:
                    print(f"    Padded data: Not available or not in expected format (e.g., empty or decryption failed before unpadding).")

            except Exception as e:
                print(f"[!] An unexpected error occurred: {e}")

    except socket.error as e:
        print(f"[!] Socket error: {e}")
    except Exception as e:
        print(f"[!] A general error occurred: {e}")

if __name__ == '__main__':
    solve()
