# Given m = c since e = 1 and c < n
m = 9327565722767258308650643213344542404592011161659991421

# Convert to bytes and decode as text
m_bytes = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big')
try:
    decoded_text = m_bytes.decode()
except UnicodeDecodeError:
    decoded_text = None

decoded_text, m_bytes.hex()  # Also provide the hex version just in case it's not plain text

print(decoded_text)