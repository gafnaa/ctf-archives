#!/usr/bin/env python3
import struct

def parse_elf_load_segment(filename, target_vaddr):
    with open(filename, 'rb') as f:
        data = f.read()

    # Validate ELF64 header
    if data[:4] != b'\x7fELF':
        raise ValueError("Not a valid ELF file")

    endian = '<' if data[5] == 1 else '>'  # little endian if 1
    e_phoff, = struct.unpack_from(endian + 'Q', data, 32)
    e_phentsize, = struct.unpack_from(endian + 'H', data, 54)
    e_phnum, = struct.unpack_from(endian + 'H', data, 56)

    # Iterate over program headers to find load segment covering target_vaddr
    for i in range(e_phnum):
        offset = e_phoff + i * e_phentsize
        p_type, = struct.unpack_from(endian + 'I', data, offset)
        if p_type != 1:  # PT_LOAD
            continue
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack_from(endian + 'QQQQQQ', data, offset+8)
        if p_vaddr <= target_vaddr < p_vaddr + p_memsz:
            file_offset = p_offset + (target_vaddr - p_vaddr)
            return data, file_offset

    raise ValueError("No PT_LOAD segment covers target vaddr")

def recover_flag_from_data(data, offset, count):
    vals = [struct.unpack_from('<I', data, offset + i*4)[0] for i in range(count)]
    flag_chars = []

    for i, v in enumerate(vals):
        m = 2 * i + 1
        if v % m != 0:
            raise ValueError(f"Value {v} at index {i} not divisible by {m}")
        x = v // m
        b0 = (x >> 8) & 0xFF
        b1 = x & 0xFF
        flag_chars.append(chr(b0))
        flag_chars.append(chr(b1))

    return ''.join(flag_chars)

if _name_ == '_main_':
    elf_filename = 'original'
    target_vaddr = 0x402360
    value_count = 35

    data, table_offset = parse_elf_load_segment(elf_filename, target_vaddr)
    flag = recover_flag_from_data(data, table_offset, value_count)

    print("Recovered flag:")
print(flag)
