def xor_hex_strings(hex_str1, hex_str2):
    """
    XORs two hexadecimal strings.
    Assumes both strings are of the same length.
    """
    bytes1 = bytes.fromhex(hex_str1)
    bytes2 = bytes.fromhex(hex_str2)
    
    if len(bytes1) != len(bytes2):
        raise ValueError("Hex strings must have the same length for XOR operation.")
        
    xor_result = bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))
    return xor_result.hex()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="XOR two hexadecimal strings.")
    parser.add_argument("hex_str1", help="First hexadecimal string")
    parser.add_argument("hex_str2", help="Second hexadecimal string")
    
    args = parser.parse_args()
    
    try:
        result = xor_hex_strings(args.hex_str1, args.hex_str2)
        print(result)
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
