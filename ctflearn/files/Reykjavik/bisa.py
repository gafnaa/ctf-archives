import struct

def to_bytes(n, length=8):
    """
    Converts a potentially signed integer to a little-endian byte string.
    The length determines the number of bytes (e.g., 8 for a 64-bit qword).
    """
    # The bitwise AND handles negative numbers by converting them to their
    # two's complement representation within the specified byte length.
    return (n & ((1 << length * 8) - 1)).to_bytes(length, 'little')

# --- Data extracted from the decompiler output ---

# Encrypted 64-bit (8-byte) integer values
data = -4190094988825198616
qword_4018 = -2478132131309359408
qword_4020 = -4194320411994688306

# Encrypted 8-bit (1-byte) character values
byte_4028 = 0xCF
byte_4029 = 0xF4
byte_402A = 0xD6

# The repeating XOR key
KEY_64BIT = 0xABABABABABABABAB
KEY_8BIT = 0xAB

# --- Decryption ---

# Perform the XOR operation for each part of the flag
part1 = data ^ KEY_64BIT
part2 = qword_4018 ^ KEY_64BIT
part3 = qword_4020 ^ KEY_64BIT
part4 = byte_4028 ^ KEY_8BIT
part5 = byte_4029 ^ KEY_8BIT
part6 = byte_402A ^ KEY_8BIT

# Convert the resulting integers to bytes (little-endian order)
# and concatenate them to form the full flag string.
flag_bytes = b"".join([
    to_bytes(part1, 8),
    to_bytes(part2, 8),
    to_bytes(part3, 8),
    to_bytes(part4, 1),
    to_bytes(part5, 1),
    to_bytes(part6, 1),
])

# Decode the final byte string into a human-readable UTF-8 string
# and remove any trailing null bytes that might be present.
flag = flag_bytes.strip(b'\x00').decode('utf-8')

print("--- Reykjavik Challenge Decryptor ---")
print(f"The decrypted flag is: {flag}")

