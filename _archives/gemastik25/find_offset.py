import argparse
import sys
from decompressor import decompress # Imports the function from your existing script

def find_correct_offset(input_file, max_offset_to_check=4096):
    """
    Tries to decompress the input file at different offsets to find the correct one.
    A successful decompression is identified by the "MZ" PE file signature.
    """
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file not found at '{input_file}'", file=sys.stderr)
        return None

    print(f"[*] Scanning '{input_file}' for the correct decompression offset (up to {max_offset_to_check} bytes)...")

    for offset in range(max_offset_to_check):
        # We need at least a few bytes to decompress something meaningful
        if offset >= len(data) - 2:
            print("[!] Reached end of file before finding a valid offset.")
            return None

        # Give a status update every 256 bytes
        if offset % 256 == 0 and offset > 0:
            print(f"    ... still scanning (at offset {offset})")

        try:
            # Get the data slice starting from the current offset
            data_slice = data[offset:]
            
            # Attempt to decompress
            decompressed_data = decompress(data_slice)
            
            # Check for the MZ header (4D 5A in hex)
            if len(decompressed_data) > 2 and decompressed_data.startswith(b'MZ'):
                print(f"\n[*] Success! Found valid PE header ('MZ') at offset: {offset}")
                print(f"    Decompressed size will be approximately {len(decompressed_data)} bytes.")
                return offset
        except Exception:
            # We expect errors when trying incorrect offsets, so we can ignore them
            continue

    print(f"\n[!] Failed to find a valid offset after checking up to {max_offset_to_check} bytes.")
    print("[!] Tip: You can try increasing the scan range with the --max-scan argument.")
    return None

def main():
    parser = argparse.ArgumentParser(
        description="Automatically find the correct starting offset for the decompressor script.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("input_file", help="Path to the compressed payload file (e.g., payload.bin).")
    parser.add_argument("--max-scan", type=int, default=4096, help="How many bytes to scan for the offset. Default is 4096.")
    args = parser.parse_args()

    correct_offset = find_correct_offset(args.input_file, max_offset_to_check=args.max_scan)
    
    if correct_offset is not None:
        print("\nNow, run the decompressor with the found offset:")
        print(f"python decompressor.py \"{args.input_file}\" unpacked.exe --offset {correct_offset}")

if __name__ == "__main__":
    main()

