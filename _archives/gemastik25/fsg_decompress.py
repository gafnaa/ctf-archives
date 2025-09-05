import sys
import argparse

# The 'pefile' library is required to parse the executable and find the data.
# We'll handle the import gracefully if the user doesn't have it installed.
try:
    import pefile
except ImportError:
    pefile = None

class FsgBitReader:
    """
    This class replicates the unusual bit-reading logic found in the FSG decompression stub.
    This new implementation is a more faithful translation of the C code's state machine,
    correctly handling how the bit buffer is reloaded when it becomes empty.
    """
    def __init__(self, data):
        self.data = data
        self.ptr = 0
        # The C code initializes its bit buffer to 0x80, which represents a single '1' bit
        # followed by seven '0' bits. This primes the pump for the first read.
        self.buffer = 0x80

    def get_bit(self):
        """Reads one bit from the compressed stream."""
        # Determine the carry/output bit from the current buffer's most significant bit (MSB).
        carry = 1 if (self.buffer & 0x80) != 0 else 0
        
        # Shift the buffer to the left to process the next bit.
        self.buffer = (self.buffer << 1) & 0xFF
        
        # The bit to be returned is the one we just shifted out (the carry).
        result_bit = carry
        
        # If the buffer is now empty (all 8 bits have been shifted out), we must reload it.
        if self.buffer == 0:
            if self.ptr >= len(self.data):
                raise EOFError("Unexpected end of compressed data during bit read.")

            new_byte = self.data[self.ptr]
            self.ptr += 1

            # CRITICAL FIX: The C code's logic dictates that when a reload occurs,
            # the bit for the current operation is the MSB of the *newly loaded byte*.
            result_bit = 1 if (new_byte & 0x80) != 0 else 0
            
            # The new buffer for the *next* operation is formed by shifting the new byte
            # and inserting the *carry from the previous byte* into the least significant bit (LSB).
            self.buffer = ((new_byte << 1) | carry) & 0xFF
            
        return result_bit

    def get_byte(self):
        """Reads one literal byte from the input stream."""
        if self.ptr >= len(self.data):
            raise EOFError("Unexpected end of compressed data.")
        byte = self.data[self.ptr]
        self.ptr += 1
        return byte

    def read_gamma_code(self):
        """
        Reads a gamma-encoded integer. This is used for decoding match lengths
        and parts of the match offset. It corresponds to the `do-while` loops
        in the C code that calculate values like `iVar4`.
        """
        value = 1
        while True:
            value = (value << 1) | self.get_bit()
            if not self.get_bit():
                break
        return value


def fsg_decompress(data):
    """
    Decompresses data that was compressed with the FSG packer.
    The logic follows the nested if/else structure of the provided C code.
    
    Args:
        data (bytes): The raw compressed byte stream.
        
    Returns:
        bytes: The decompressed data.
    """
    if not data:
        return b""

    output = bytearray()
    # CRITICAL LOGIC CHANGE: The first byte is always copied literally, and the bit
    # reader should only start processing from the *second* byte onwards.
    output.append(data[0])
    
    # Initialize the bit reader on the rest of the data stream.
    reader = FsgBitReader(data[1:])
    
    last_offset = 0
    # Corresponds to iVar6 in C. It's set to 2 after the first literal copy.
    lwm_state = 2

    while True:
        # Read the main flag bit to decide between a literal or a match.
        if reader.get_bit() == 0:
            # FLAG 0: Literal byte.
            output.append(reader.get_byte())
            lwm_state = 2 # After a literal, the state is 2.
            continue

        # FLAG 1: It's a match (a length-distance copy).
        if reader.get_bit() == 0:
            # FLAG 10: Long match or repeat of last offset.
            length_part = reader.read_gamma_code()
            
            length = length_part - lwm_state
            
            offset_high = reader.read_gamma_code() - 2
            
            if offset_high != 0xFFFFFFFF: # Check for -1
                offset = (offset_high << 8) + reader.get_byte()
                last_offset = offset
            else:
                offset = last_offset
                
            length += 3 # Minimum length for this type of match

            if offset >= 32000: length += 1
            if offset < 128: length += 2
            
            # After this type of match, the state for the next round is 1.
            lwm_state = 1

        else:
            # FLAG 11: Shorter match types.
            if reader.get_bit() == 0:
                # FLAG 110: Short match with length 2 or 3.
                byte = reader.get_byte()
                offset = byte >> 1
                if offset == 0:
                    # An offset of 0 is the end-of-stream marker.
                    print("End of stream marker found.")
                    break
                length = (byte & 1) + 2
                last_offset = offset
                # After this type of match, the state for the next round is 1.
                lwm_state = 1
            else:
                # FLAG 111: Very short match, length 1, or literal 0.
                offset = 0
                for _ in range(4):
                    offset = (offset << 1) | reader.get_bit()
                
                if offset == 0:
                    # Special case: append a literal zero byte.
                    output.append(0)
                    lwm_state = 2 # A literal 0 behaves like a literal copy.
                    continue
                
                length = 1
                last_offset = offset
                # After this type of match, the state for the next round is 2.
                lwm_state = 2

        # Perform the copy operation for the match.
        try:
            for _ in range(length):
                output.append(output[-offset])
        except IndexError:
            # Add more detail to the error message for better debugging.
            raise RuntimeError(f"Invalid copy operation: offset {offset} with length {length} is too large for current output size {len(output)}")

    return bytes(output)

def extract_fsg_section(filepath):
    """
    Parses a PE file and extracts the raw data from the last section.
    FSG typically stores its compressed data in the last section of the executable.
    
    Args:
        filepath (str): The path to the packed executable file.
        
    Returns:
        bytes: The raw data of the last section.
    """
    print("-> Parsing PE file to find compressed data...")
    try:
        pe = pefile.PE(filepath, fast_load=True)
        # The compressed data is in the last PE section
        last_section = pe.sections[-1]
        section_name = last_section.Name.decode().strip('\x00')
        print(f"-> Found last section: '{section_name}'")
        print(f"-> Extracting {last_section.SizeOfRawData} bytes of compressed data.")
        return last_section.get_data()
    except pefile.PEFormatError as e:
        raise ValueError(f"'{filepath}' does not appear to be a valid PE file: {e}")
    except IndexError:
        raise ValueError(f"Could not find any sections in '{filepath}'.")

def main():
    """Main function to run the script from the command line."""
    parser = argparse.ArgumentParser(
        description="Decompresses FSG-packed executable files by automatically extracting the last section.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Example usage:
  python fsg_decompress.py packed_executable.exe decompressed_file.exe

If decompression fails, you can try specifying a start offset within the data section.
Some packers prepend metadata (like the original file size) to the stream.

Example with an offset:
  python fsg_decompress.py packed_executable.exe decompressed_file.exe --offset 4

NOTE: This script requires the 'pefile' library. You must install it first:
  pip install pefile
"""
    )
    parser.add_argument("infile", help="Path to the input packed executable file.")
    parser.add_argument("outfile", help="Path to write the output decompressed file.")
    parser.add_argument("--offset", type=int, default=0, help="Start offset within the extracted section data to begin decompression.")
    
    args = parser.parse_args()

    if pefile is None:
        print("Error: The 'pefile' library is required but not installed.", file=sys.stderr)
        print("Please install it by running: pip install pefile", file=sys.stderr)
        sys.exit(1)

    try:
        print(f"Reading packed executable from '{args.infile}'...")
        # Automatically extract the compressed data from the PE file
        compressed_data = extract_fsg_section(args.infile)
        
        if args.offset > 0:
            if args.offset >= len(compressed_data):
                print(f"Error: offset {args.offset} is larger than the section size {len(compressed_data)}", file=sys.stderr)
                sys.exit(1)
            print(f"-> Applying offset: starting decompression from byte {args.offset} of the section.")
            compressed_data = compressed_data[args.offset:]
            
        print(f"Decompressing {len(compressed_data)} bytes...")
        decompressed_data = fsg_decompress(compressed_data)
        
        print(f"Writing {len(decompressed_data)} decompressed bytes to '{args.outfile}'...")
        with open(args.outfile, 'wb') as f_out:
            f_out.write(decompressed_data)
            
        print("\nDecompression complete!")

    except FileNotFoundError:
        print(f"Error: Input file not found at '{args.infile}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\nAn error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

