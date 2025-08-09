import struct
import hashlib

def main():
    """
    This script decrypts the data found in the POK lab by simulating the
    provided assembly code. This version contains the corrected logic for section 'four'.
    """
    # The qword data from the binary, loaded as a little-endian byte stream.
    qwords = [
        14665569304904511663, 5385794698809859774, 13825184220745982910,
        18416225818507988683, 18026904693940997814
    ]
    data = b''.join(struct.pack('<Q', q) for q in qwords)

    # The output buffer for the decrypted flag.
    result = bytearray(40)
    
    # Pointers to navigate through the data (rax) and result (rcx) buffers.
    rax = 0
    rcx = 0

    # --- Section 'one': Decrypts the first 8 bytes ---
    for _ in range(8):
        byte = data[rax]
        byte = (byte ^ 0x69) & 0xFF
        byte = (byte + 0xe7) & 0xFF
        byte = (byte + 0x19) & 0xFF
        byte = (byte ^ 0x96) & 0xFF
        result[rcx] = byte
        rax += 1
        rcx += 1

    # --- Section 'two': Decrypts the next 4 bytes (processing 2 bytes at a time) ---
    for _ in range(4):
        word = struct.unpack('<H', data[rax:rax+2])[0]
        word = (word + 0xbe) & 0xFFFF
        word = (word ^ 0x42) & 0xFFFF
        word = word >> 4
        
        low_byte = word & 0xFF
        high_byte = word >> 8
        low_byte = (low_byte ^ 0x4) & 0xFF
        word = (high_byte << 8) | low_byte
        
        word = word >> 4
        result[rcx] = word & 0xFF
        rax += 2
        rcx += 1

    # --- Section 'three': Decrypts the next 8 bytes (processing 2 bytes at a time) ---
    mask = 0xFEFF
    for _ in range(4):
        word = struct.unpack('<H', data[rax:rax+2])[0]
        word &= mask
        
        # This sequence performs a byte swap, a right shift, and another byte swap.
        word = ((word << 8) | (word >> 8)) & 0xFFFF # Byte swap
        word >>= 1
        word = ((word << 8) | (word >> 8)) & 0xFFFF # Byte swap
        
        struct.pack_into('<H', result, rcx, word)
        rax += 2
        rcx += 2

    # --- Section 'four': A multi-part decryption process (Corrected Logic) ---
    # Part 1: Decrypts 4 bytes
    dword = struct.unpack('<I', data[rax:rax+4])[0]
    dword = (~dword) & 0xFFFFFFFF
    dword = (dword << 2) & 0xFFFFFFFF
    
    # inc bl
    low_byte = dword & 0xFF
    low_byte = (low_byte + 1) & 0xFF
    dword = (dword & 0xFFFFFF00) | low_byte
    
    dword = (dword << 2) & 0xFFFFFFFF
    
    # add bl, 0x3
    low_byte = dword & 0xFF
    low_byte = (low_byte + 3) & 0xFF
    dword = (dword & 0xFFFFFF00) | low_byte
    
    dword = (dword << 3) & 0xFFFFFFFF
    
    # sub bl, 0xfd
    low_byte = dword & 0xFF
    low_byte = (low_byte - 0xfd) & 0xFF
    dword = (dword & 0xFFFFFF00) | low_byte
    
    dword = (dword << 1) & 0xFFFFFFFF
    
    # inc bl
    low_byte = dword & 0xFF
    low_byte = (low_byte + 1) & 0xFF
    dword = (dword & 0xFFFFFF00) | low_byte
    
    struct.pack_into('<I', result, rcx, dword)
    rax += 4
    rcx += 4
    
    # Part 2: Inserts a constant character '_'
    result[rcx] = 0x5f
    rcx += 1
    
    # Part 3: Decrypts another 4 bytes
    dword = struct.unpack('<I', data[rax:rax+4])[0]
    dword = (~dword) & 0xFFFFFFFF
    dword = (dword << 4) & 0xFFFFFFFF
    
    # inc bl
    low_byte = dword & 0xFF
    low_byte = (low_byte + 1) & 0xFF
    dword = (dword & 0xFFFFFF00) | low_byte
    
    # xor bl, 0x6
    low_byte = dword & 0xFF
    low_byte = (low_byte ^ 6) & 0xFF
    dword = (dword & 0xFFFFFF00) | low_byte
    
    dword = (dword << 2) & 0xFFFFFFFF

    # inc bl
    low_byte = dword & 0xFF
    low_byte = (low_byte + 1) & 0xFF
    dword = (dword & 0xFFFFFF00) | low_byte
    
    dword = (dword << 2) & 0xFFFFFFFF
    struct.pack_into('<I', result, rcx, dword)
    rax += 4
    rcx += 4

    # --- Section 'five': Decrypts the final 8 bytes ---
    qword = struct.unpack('<Q', data[rax:rax+8])[0]
    qword >>= 1 # Discard the least significant bit
    
    # Reverses the bits of the remaining 63-bit value
    rev_qword = 0
    temp_qword = qword
    # The loop in assembly runs until the value is 0.
    # The MSB of the shifted qword is at bit 62, so we loop 63 times.
    for i in range(63):
        rev_qword <<= 1
        if temp_qword & 1:
            rev_qword |= 1
        temp_qword >>= 1
            
    struct.pack_into('<Q', result, rcx, rev_qword)

    # --- Finalization ---
    # The decrypted flag is the resulting bytes, trimmed of nulls.
    decrypted_flag = result.strip(b'\x00').decode('utf-8')
    print(f"Decrypted Flag: {decrypted_flag}")

    # Append the sha256 hash as per the instructions.
    flag_hash = hashlib.sha256(decrypted_flag.encode()).hexdigest()[:10]
    final_flag = f"COMPFEST17{{{decrypted_flag}_{flag_hash}}}"
    
    print(f"Final Flag: {final_flag}")

if __name__ == '__main__':
    main()
