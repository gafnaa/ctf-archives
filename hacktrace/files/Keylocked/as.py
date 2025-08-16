# TODO: Fill these variables with the data you extract from the executable.
#
# Example:
# chunk_a = b"\xde\xad\xbe\xef"
# chunk_b = b"\xca\xfe\xba\xbe"
# order = [4, 0, 5, 1, 6, 2, 7, 3]

chunk_a = b""
chunk_b = b""
order = []

# 1. Combine the two data chunks
combined_data = chunk_a + chunk_b

# 2. Initialize an empty list to build the flag
flag_bytes = []

# 3. Reorder the bytes according to the 'order' array
for index in order:
    # Check if the index is valid
    if index < len(combined_data):
        flag_bytes.append(combined_data[index])
    else:
        print(f"Error: Index {index} is out of bounds for combined data of length {len(combined_data)}")

# 4. Join the bytes and decode to a readable string
# The final flag might be in UTF-8 or simple ASCII format.
try:
    flag = bytes(flag_bytes).decode('utf-8')
    print("Successfully decrypted!")
    print("FLAG:", flag)
except UnicodeDecodeError:
    print("Could not decode as UTF-8. Here are the raw bytes:")
    print(bytes(flag_bytes))