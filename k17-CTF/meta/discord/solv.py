
data = """;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;"""


mapping = {
    ';': '0',       # U+003B normal semicolon
    ';': '1',       # U+037E Greek question mark (looks like semicolon)
}

binary = ''.join(mapping.get(ch, '') for ch in data)
flag = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8))

print(flag)
