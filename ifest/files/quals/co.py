#!/usr/bin/env python3
import struct

def main():
    with open('original', 'rb') as f:
        data = f.read()
  
    vaddr = 0x402360
    file_offset = data.find(b'\x46\x49\x00\x00')  # Bisa diganti hardcoded offset langsung
    count = 35
    flag = ""

    for i in range(count):
        val = struct.unpack_from('<I', data, file_offset + i*4)[0]
        x = val // (2*i + 1)
        flag += chr((x >> 8) & 0xFF)
        flag += chr(x & 0xFF)

    print(flag)

if __name__ == '__main__':
    main()
