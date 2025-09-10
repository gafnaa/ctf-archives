import re
import binascii

# Read the dump file
with open('dump.txt', 'r', encoding='utf-8', errors='ignore') as f:
    dump = f.read()

# Extract flag chunks
flag_chunks = {}
chunk_pattern = r'X-Flag-Chunk-(\d+):\s*([A-Fa-f0-9]+)'
matches = re.finditer(chunk_pattern, dump)

for match in matches:
    chunk_num = int(match.group(1))
    chunk_data = match.group(2)
    flag_chunks[chunk_num] = chunk_data

# Get total number of chunks
total_pattern = r'X-Flag-Total:\s*(\d+)'
total_match = re.search(total_pattern, dump)
total_chunks = int(total_match.group(1)) if total_match else 0

print(f"Found {len(flag_chunks)} chunks out of {total_chunks} total")

# Combine chunks in order
combined_hex = ''
for i in range(total_chunks):
    if i in flag_chunks:
        combined_hex += flag_chunks[i]
    else:
        print(f"Missing chunk {i}")

# Convert hex to binary
binary_data = binascii.unhexlify(combined_hex)

# Save as PNG
with open('flag.png', 'wb') as f:
    f.write(binary_data)

print("Saved flag.png")