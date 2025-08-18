plaintext = b'H\xcb\xcb*~h0\xa0\xdd\xa7\x1eT\x19\xb6a\xce\x836\xfeH<\xef\xea\xe9\x07M\xfa=\xed\xdf\x92\xff,\xb9:\xe3\xcb\x7f\x96^\xbc\xf2\xdf\xe5\x97\x1f\x9c{2\xdf\xe7\x87\xb6[\xf9\xb7\xf2\xbf\xc3\x96\x9d\xb9y\xfd'

# Step 1: Convert to bitstream (binary string)
bitstream = ''.join(f'{byte:08b}' for byte in plaintext)

# Step 2: Try all bit offsets from 0 to 7
for offset in range(8):
    shifted_bits = bitstream[offset:]
    chars = []
    for i in range(0, len(shifted_bits) - 7, 7):
        group = shifted_bits[i:i+7]
        char_code = int(group, 2)
        chars.append(chr(char_code))
    result = ''.join(chars)
    print(f"Offset {offset}: {result}")
