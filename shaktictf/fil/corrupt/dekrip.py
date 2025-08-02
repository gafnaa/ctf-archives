import sys

def decrypt_payload(input_file_path, output_file_path):
    """
    Decrypts a file that has been XOR-encrypted with a repeating key.

    Args:
        input_file_path (str): The path to the encrypted file (e.g., 'extracted_data.bin').
        output_file_path (str): The path to save the decrypted payload to.
    """
    # The 5-byte key identified from the repetitive patterns in the source data.
    key = b'\x35\x4B\x50\xb3\x04'
    decrypted_data = bytearray()

    try:
        with open(input_file_path, 'rb') as f_in:
            encrypted_data = f_in.read()

        # Loop through the encrypted data, XORing each byte with the key
        for i in range(len(encrypted_data)):
            decrypted_byte = encrypted_data[i] ^ key[i % len(key)]
            decrypted_data.append(decrypted_byte)

        with open(output_file_path, 'wb') as f_out:
            f_out.write(decrypted_data)

        print(f"✅ Decryption complete! Payload saved to '{output_file_path}'")
        print(f"   - Key Used (bytes): {key}")
        print(f"   - Payload Size: {len(decrypted_data)} bytes")


    except FileNotFoundError:
        print(f"❌ Error: Input file '{input_file_path}' not found.", file=sys.stderr)
        print("   Please make sure 'extracted_data.bin' is in the same directory.", file=sys.stderr)
    except Exception as e:
        print(f"❌ An error occurred: {e}", file=sys.stderr)


if __name__ == "__main__":
    input_file = "extracted_data.bin"
    output_file = "decrypted_payload.bin"
    decrypt_payload(input_file, output_file)
