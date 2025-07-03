baconian = {
'a': '00000',	'b': '00001',
'c': '00010',	'd': '00011',
'e': '00100',	'f': '00101',
'g': '00110',	'h': '00111',
'i': '01000',    'j': '01000', # 'j' maps to 'i's code
'k': '01001',    'l': '01010',
'm': '01011',    'n': '01100',
'o': '01101',    'p': '01110',
'q': '01111',    'r': '10000',
's': '10001',    't': '10010',
'u': '10011',    'v': '10011', # 'v' maps to 'u's code
'w': '10100',	'x': '10101',
'y': '10110',	'z': '10111'}

# Create inverse Baconian dictionary
inv_baconian = {}
for char, code in baconian.items():
    # Prioritize 'i' over 'j' and 'u' over 'v' as per standard Baconian
    if code not in inv_baconian:
        inv_baconian[code] = char
    elif char == 'i': # Ensure 'i' is preferred if both 'i' and 'j' map to the same code
        inv_baconian[code] = char
    elif char == 'u': # Ensure 'u' is preferred if both 'u' and 'v' map to the same code
        inv_baconian[code] = char

# Read out.txt
with open('files/out.txt', 'r') as f:
    encrypted_output = f.read().strip()

# Reverse Caesar cipher (add 13)
caesar_reversed_text = ""
for char_code in encrypted_output:
    caesar_reversed_text += chr(ord(char_code) + 13)

# Reconstruct Baconian bits and decode
flag_chars = []
for i in range(0, len(caesar_reversed_text), 5):
    chunk = caesar_reversed_text[i:i+5]
    
    bacon_code = ""
    for char in chunk:
        if char.isupper():
            bacon_code += '1'
        elif char.islower():
            bacon_code += '0'
        else:
            # Handle non-alphabetic characters if any, though based on enc.py, it should be all alpha
            # If there are non-alpha chars, it means the original text.txt had them.
            # For now, assume only alpha chars are in the relevant parts.
            print(f"Warning: Non-alphabetic character '{char}' found in chunk '{chunk}'")
            bacon_code += '?' # Placeholder for unknown

    if bacon_code in inv_baconian:
        flag_chars.append(inv_baconian[bacon_code])
    else:
        print(f"Warning: Unknown Baconian code '{bacon_code}' for chunk '{chunk}'")
        flag_chars.append('?') # Placeholder for unknown code

flag = "".join(flag_chars)
print(f"Decoded flag: {flag}")
