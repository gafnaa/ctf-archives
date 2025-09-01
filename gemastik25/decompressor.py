import argparse
import sys

class BitStream:
    """A helper class to read bits from a byte stream."""
    def __init__(self, data):
        self.data = data
        self.byte_pos = 0
        self.bit_pos = 7
        self.current_byte = self.data[self.byte_pos] if self.data else 0

    def read_bit(self):
        self.bit_pos += 1
        if self.bit_pos > 7:
            self.byte_pos += 1
            if self.byte_pos >= len(self.data):
                raise IndexError("Attempted to read past the end of the data stream.")
            self.current_byte = self.data[self.byte_pos]
            self.bit_pos = 0
        
        # Read the bit (MSB first)
        bit = (self.current_byte >> (7 - self.bit_pos)) & 1
        return bit

    def read_byte(self):
        self.byte_pos += 1
        if self.byte_pos >= len(self.data):
            raise IndexError("Attempted to read a full byte past the end of the data stream.")
        return self.data[self.byte_pos]

def decompress(data):
    """
    Decompresses the data using the reverse-engineered Themida/LZ77 algorithm.
    """
    stream = BitStream(data)
    output = bytearray()
    
    # The first byte is always a literal
    output.append(stream.data[0])
    
    last_long_offset = 0
    
    while True:
        # Mode 1: Literal copy
        if stream.read_bit() == 0:
            output.append(stream.read_byte())
            continue

        # Mode 2: Dictionary copy (back-reference)
        if stream.read_bit() == 0:
            # Short or Medium offset
            b = stream.read_byte()
            offset_val = b >> 1

            if offset_val == 0:
                # End of stream marker
                return output

            length = (b & 1) + 2
            
            if length > offset_val:
                raise ValueError(f"Invalid short offset: length {length} > offset {offset_val}")

            for _ in range(length):
                output.append(output[-offset_val])
        else:
            # Medium or Long offset
            if stream.read_bit() == 0:
                # Medium offset
                bits = [stream.read_bit() for _ in range(4)]
                offset = ((((bits[0] * 2 + bits[1]) * 2 + bits[2]) * 2 + bits[3])) + 1

                if offset == 1: # Represents a literal, not a back-reference
                    output.append(stream.data[stream.byte_pos + 1])
                    stream.byte_pos +=1
                else:
                    length = 2
                    val = 2
                    while val >= 2:
                        val = stream.read_bit() * 2 + stream.read_bit()
                        length += val
                    
                    if length > offset:
                         raise ValueError(f"Invalid medium offset")
                    for _ in range(length):
                        output.append(output[-offset])
            else:
                # Long offset
                val1 = 2
                while stream.read_bit() == 1:
                    val1 += 1

                if val1 == 2: # Mode 1 long
                    val2 = 2
                    while stream.read_bit() == 1:
                        val2 += 1
                    
                    match_len = 2
                    val3 = 2
                    while val3 >= 2:
                        val3 = stream.read_bit() * 2 + stream.read_bit()
                        match_len += val3
                    
                    last_long_offset = ((val2 - 2) << 8) | stream.read_byte()
                    
                    # This is the crucial part that was likely misinterpreted before.
                    # The original C code modifies the match length based on the offset range,
                    # it does not throw an error.
                    if last_long_offset >= 32000 or last_long_offset < 128:
                        match_len += 2
                    elif last_long_offset > 1279:
                        match_len += 1
                    
                    if match_len > last_long_offset:
                         raise ValueError(f"Invalid long offset: {last_long_offset}")

                    for _ in range(match_len):
                        output.append(output[-last_long_offset])
                else: # Mode 2 long
                    match_len = 2
                    val3 = 2
                    while val3 >= 2:
                        val3 = stream.read_bit() * 2 + stream.read_bit()
                        match_len += val3
                    
                    if match_len > last_long_offset:
                         raise ValueError(f"Invalid long offset: {last_long_offset}")
                    for _ in range(match_len):
                         output.append(output[-last_long_offset])

def main():
    parser = argparse.ArgumentParser(description="Decompress a file packed with a specific Themida LZ77 variant.")
    parser.add_argument("input_file", help="Path to the compressed payload file (e.g., payload.bin).")
    parser.add_argument("output_file", help="Path to write the decompressed output (e.g., unpacked.exe).")
    parser.add_argument("--offset", type=int, default=0, help="Start reading from this offset in the input file.")
    args = parser.parse_args()

    try:
        with open(args.input_file, 'rb') as f:
            f.seek(args.offset)
            data = f.read()
        print(f"[*] Read {len(data)} bytes from '{args.input_file}' starting at offset {args.offset}")
        
        decompressed_data = decompress(data)
        
        with open(args.output_file, 'wb') as f:
            f.write(decompressed_data)
        print(f"[+] Decompressed {len(decompressed_data)} bytes to '{args.output_file}'")

    except FileNotFoundError:
        print(f"Error: Input file not found at '{args.input_file}'", file=sys.stderr)
    except IndexError:
        print("An error occurred during decompression: The process tried to read beyond the end of the file.", file=sys.stderr)
        print("This often means the starting offset is incorrect or the data is corrupt.", file=sys.stderr)
    except Exception as e:
        print(f"An error occurred during decompression: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()

