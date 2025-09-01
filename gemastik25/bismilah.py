import sys
import argparse
import pefile

class BitReaderMSB:
    """
    Reads data from a byte stream, bit by bit, starting from the Most Significant Bit (MSB).
    This implementation now correctly matches the logic in the decompiled C code.
    """
    def __init__(self, data):
        self.data = data
        self.byte_pos = 0
        self.bit_mask = 0
        self.current_byte = 0

    def get_bit(self):
        """Reads a single bit from the stream."""
        # If the current byte has been fully read (mask is 0), load the next one.
        if self.bit_mask == 0:
            if self.byte_pos >= len(self.data):
                raise EOFError("End of stream reached while trying to read a bit.")
            self.current_byte = self.data[self.byte_pos]
            self.byte_pos += 1
            self.bit_mask = 0x80  # Start with the MSB
        
        bit = 1 if (self.current_byte & self.bit_mask) else 0
        self.bit_mask >>= 1  # Move to the next bit (MSB to LSB)
             
        return bit

    def read_byte(self):
        """Reads a single whole byte from the stream, resetting bit alignment."""
        # Force alignment to the next byte by resetting the bitmask
        self.bit_mask = 0
        if self.byte_pos >= len(self.data):
            raise EOFError("End of stream reached while trying to read a byte.")
        val = self.data[self.byte_pos]
        self.byte_pos += 1
        return val
        
    def read_bits(self, n):
        """Reads a specified number of bits and returns them as an integer."""
        val = 0
        for _ in range(n):
            # The first bit read becomes the MSB of the resulting number.
            val = (val << 1) | self.get_bit()
        return val

def read_gamma_code(stream):
    """
    Decodes a variable-length integer using gamma coding.
    This pattern appears multiple times in the source algorithm.
    """
    value = 1
    while True:
        value = (value << 1) | stream.get_bit()
        if stream.get_bit() == 0:
            break
    return value

def decompress(data):
    """
    Decompresses data using the reverse-engineered aPLib-style algorithm.

    Args:
        data (bytes): The compressed input data.

    Returns:
        bytearray: The decompressed output data.
    """
    if not data:
        return bytearray()

    # The original C code unconditionally copies the first byte.
    # The bitwise decompression then starts from the *second* byte.
    out = bytearray([data[0]])
    stream = BitReaderMSB(data[1:]) # Use the corrected MSB Bit Reader
    last_offset = 0
    
    # This state variable (iVar6 in the C code) is crucial.
    lwm_tag = 2

    # The main decompression loop.
    while True:
        try:
            # Read a control bit. If 0, it's a literal. If 1, it's an LZ match.
            if stream.get_bit() == 0:
                # A '0' bit indicates a literal byte follows.
                out.append(stream.read_byte())
                lwm_tag = 2
                continue

            # A '1' bit indicates a back-reference (LZ match).
            if stream.get_bit() == 1: # Code starts with '11'
                if stream.get_bit() == 1: # Code '111'
                    # Short match (1 byte) with a 4-bit offset.
                    offset = stream.read_bits(4)
                    if offset == 0:
                        out.append(0)
                    else:
                        if offset > len(out): raise ValueError(f"Invalid offset: {offset}")
                        out.append(out[-offset])
                    lwm_tag = 2
                else: # Code '110'
                    # Medium match (2-3 bytes) with a 7-bit offset.
                    byte = stream.read_byte()
                    offset = byte >> 1
                    if offset == 0:
                        return out # End of data marker
                    
                    length = (byte & 1) + 2
                    last_offset = offset

                    if offset > len(out): raise ValueError(f"Invalid offset: {offset}")
                    for _ in range(length):
                        out.append(out[-offset])
                    # This type of match sets the state for the next '10' block.
                    lwm_tag = 1
            else: # Code starts with '10'
                # Long match with variable length and offset.
                len_prefix = read_gamma_code(stream)
                
                check_val = len_prefix - lwm_tag
                if check_val == 0:
                    # Use the same offset as the previous match.
                    offset = last_offset
                    length = read_gamma_code(stream)
                else:
                    # Calculate a new offset.
                    offset_high = check_val - 1
                    offset = (offset_high << 8) | stream.read_byte()
                    
                    length = read_gamma_code(stream)
                    
                    # Peculiar length adjustment based on offset.
                    if offset >= 32000 or offset < 128:
                        length += 2
                    elif offset >= 1280:
                        length += 1
                    
                    last_offset = offset

                if offset > len(out): raise ValueError(f"Invalid offset: {offset}")
                for _ in range(length):
                    out.append(out[-offset])
                
                lwm_tag = 2

        except EOFError:
            # Reaching the end of the file is the natural way for the loop to end.
            break
            
    return out

def main():
    """Main function to handle command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Decompress a file that was compressed with a specific aPLib variant.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("infile", help="The path to the compressed input file (PE executable).")
    parser.add_argument("outfile", help="The path to write the decompressed output file to.")
    
    args = parser.parse_args()

    try:
        print(f"[*] Parsing PE file '{args.infile}'...")
        pe = pefile.PE(args.infile)
        
        last_section = pe.sections[-1]
        section_name = last_section.Name.decode().strip('\x00')
        print(f"[*] Found target section '{section_name}' at offset {hex(last_section.PointerToRawData)}.")
        
        compressed_data = last_section.get_data()
        
        print(f"[*] Extracted {len(compressed_data)} bytes. Decompressing data...")
        decompressed_data = decompress(compressed_data)
        
        print(f"[*] Writing {len(decompressed_data)} decompressed bytes to '{args.outfile}'...")
        with open(args.outfile, 'wb') as f_out:
            f_out.write(decompressed_data)
            
        print("[+] Decompression successful!")

    except FileNotFoundError:
        print(f"[!] Error: Input file not found at '{args.infile}'", file=sys.stderr)
    except pefile.PEFormatError as e:
        print(f"[!] Error: Not a valid PE file. {e}", file=sys.stderr)
    except Exception as e:
        print(f"[!] An error occurred during decompression: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

