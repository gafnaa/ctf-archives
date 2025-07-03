import struct

# The encrypted 8-byte (QWORD) values from the binary
data = 0xCFD8D5D8D9C5D4D4
qword_4018 = 0x9DDAD59FF29C9A98
qword_4020 = 0x9D9A8D9A8D9A8D9A

# The encrypted single byte values
byte_4028 = 0x9D
byte_4029 = 0xD4
byte_402A = 0xDF

# The XOR keys
key_64bit = 0xABABABABABABABAB
key_8bit = 0xAB

# Perform the XOR operations
# struct.pack('<Q', ...) packs the 64-bit integer into 8 bytes using little-endian format
v6_0_decrypted = struct.pack('<Q', data ^ key_64bit)
v6_1_decrypted = struct.pack('<Q', qword_4018 ^ key_64bit)
v6_2_decrypted = struct.pack('<Q', qword_4020 ^ key_64bit)

v7_decrypted = struct.pack('B', byte_4028 ^ key_8bit)
v8_decrypted = struct.pack('B', byte_4029 ^ key_8bit)
v9_decrypted = struct.pack('B', byte_402A ^ key_8bit)

# The C code assembles the final string in this order in memory
# v6[0], v6[1], v6[2], v7, v8, v9
final_flag = (v6_0_decrypted + v6_1_decrypted + v6_2_decrypted + 
              v7_decrypted + v8_decrypted + v9_decrypted)

# Decode from bytes to a readable string
print(final_flag.decode('ascii'))
