#!/usr/bin/env python3
import struct

def get_data_at_vaddr(elf_file, vaddr):
    with open(elf_file, 'rb') as f:
        data = f.read()

    if data[:4] != b'\x7fELF':
        raise ValueError("Not an ELF file")

    endian = '<' if data[5] == 1 else '>'  # 1 = little endian
    e_phoff = struct.unpack_from(endian + 'Q', data, 32)[0]
    e_phentsize = struct.unpack_from(endian + 'H', data, 54)[0]
    e_phnum = struct.unpack_from(endian + 'H', data, 56)[0]

    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from(endian + 'I', data, off)[0]
        if p_type != 1:  # PT_LOAD
            continue

        p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(endian + 'QQQQQQ', data, off + 8)
        if p_vaddr <= vaddr < p_vaddr + p_memsz:
            file_offset = p_offset + (vaddr - p_vaddr)
            return data, file_offset

    raise Exception("Target virtual address not found in loadable segment")

def extract_flag(data, offset, count):
    flag = ""
    for i in range(count):
        val = struct.unpack_from('<I', data, offset + i * 4)[0]
        x = val // (2 * i + 1)
        high = (x >> 8) & 0xFF
        low = x & 0xFF
        flag += chr(high) + chr(low)
    return flag

if __name__ == '__main__':
    elf = 'original'
    vaddr = 0x402360
    count = 35

    data, offset = get_data_at_vaddr(elf, vaddr)
    flag = extract_flag(data, offset, count)

    print("Recovered flag:")
    print(flag)
