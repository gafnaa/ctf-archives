import ast

def hex2bin(msg):
    """Converts a hexadecimal string to its binary representation."""
    num_of_bits = len(msg) * 4
    return bin(int(msg, 16))[2:].zfill(num_of_bits)

def find_error_pos(encoded_binary):
    """
    Calculates the error position (syndrome) in a Hamming-encoded binary string.
    Returns the 1-indexed position of the error.
    """
    syndrome = 0
    n = len(encoded_binary)
    for i in range(n):
        if encoded_binary[i] == '1':
            syndrome ^= (i + 1)
    return syndrome

# --- Main execution ---

try:
    with open('output.txt', 'r') as f:
        file_content = f.read()
    output_data = ast.literal_eval(file_content)
except FileNotFoundError:
    print("Error: 'output.txt' not found. Please create it in the same directory.")
    exit()
except Exception as e:
    print(f"Error parsing 'output.txt': {e}")
    exit()

flag_binary = ""

for entry in output_data:
    hex_code = entry[0]
    given_pos_0_indexed = entry[1]

    binary_code = hex2bin(hex_code)
    unreversed_code = binary_code[::-1]
    
    calculated_error_pos_1_indexed = find_error_pos(unreversed_code)
    calculated_error_pos_0_indexed = calculated_error_pos_1_indexed - 1

    if calculated_error_pos_0_indexed == given_pos_0_indexed:
        flag_binary += '1'
    else:
        flag_binary += '0'

# --- Robust Decoding and Output ---

print(f"Recovered Binary String ({len(flag_binary)} bits):\n{flag_binary}\n")

flag_text = ""
try:
    # Convert binary string to a bytes object
    num_bytes = (len(flag_binary) + 7) // 8
    flag_bytes = int(flag_binary, 2).to_bytes(num_bytes, byteorder='big')
    
    # Decode the bytes object into a string, replacing invalid characters
    # with a placeholder ''
    flag_text = flag_bytes.decode('ascii', errors='replace')

except Exception as e:
    flag_text = f"[An error occurred during decoding: {e}]"

print(f"✅ Recovered Flag (with error replacement):\n{flag_text}")