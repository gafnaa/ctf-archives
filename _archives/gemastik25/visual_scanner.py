import argparse
import sys
import numpy as np
import matplotlib.pyplot as plt
from decompressor import decompress

def calculate_entropy(data, window_size=256):
    """Calculates the Shannon entropy over a sliding window."""
    # Ensure data is a numpy array
    if not isinstance(data, np.ndarray):
        data = np.frombuffer(data, dtype=np.uint8)

    shape = (data.shape[0] - window_size + 1, window_size)
    strides = (data.strides[0], data.strides[0])
    windows = np.lib.stride_tricks.as_strided(data, shape=shape, strides=strides)

    # Count occurrences of each byte value in each window
    counts = np.apply_along_axis(lambda x: np.bincount(x, minlength=256), 1, windows)
    
    # Calculate probabilities
    probs = counts / window_size
    
    # Calculate Shannon entropy
    # We use np.ma.log2 to handle log(0) gracefully
    entropy = -np.sum(np.ma.log2(probs) * probs, axis=1)
    
    return entropy.filled(0) # fill -inf with 0

def plot_entropy(input_file):
    """Reads a file, calculates its entropy, and saves a plot."""
    print(f"[*] Analyzing entropy for '{input_file}'...")
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        if len(data) < 512:
            print("[!] File is too small for meaningful entropy analysis. Skipping plot.")
            return

        entropy = calculate_entropy(data)
        
        plt.figure(figsize=(15, 6))
        plt.plot(entropy)
        plt.title(f'Shannon Entropy of {input_file}')
        plt.xlabel('Offset (Byte Window)')
        plt.ylabel('Entropy (bits)')
        plt.grid(True)
        
        plot_filename = 'entropy_plot.png'
        plt.savefig(plot_filename)
        print(f"[+] Entropy plot saved to '{plot_filename}'.")
        print("[+] Look for a sharp, sustained rise in the graph. The decompression offset is likely near that point.")

    except ImportError:
        print("\n[!] Warning: `matplotlib` or `numpy` is not installed.", file=sys.stderr)
        print("    Cannot generate entropy plot. Please install them by running:", file=sys.stderr)
        print("    pip install matplotlib numpy", file=sys.stderr)
    except Exception as e:
        print(f"\n[!] An error occurred during entropy analysis: {e}", file=sys.stderr)

def find_correct_offset(input_file):
    """
    Tries to decompress the input file at different offsets to find the correct one
    by scanning the entire file.
    """
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: Input file not found at '{input_file}'", file=sys.stderr)
        return None

    total_size = len(data)
    print(f"[*] Starting full scan of '{input_file}' ({total_size} bytes) to find correct offset...")

    # A simple single-line progress indicator
    update_interval = max(1, total_size // 100) # Update every 1%

    for offset in range(total_size):
        if offset % update_interval == 0:
            percent_complete = (offset * 100) // total_size
            print(f"\r    ... scanning ({percent_complete}%)", end="", flush=True)

        if offset >= total_size - 2:
            break

        try:
            data_slice = data[offset:]
            decompressed_data = decompress(data_slice)
            
            if len(decompressed_data) > 2 and decompressed_data.startswith(b'MZ'):
                print(f"\n\n[*] Success! Found valid PE header ('MZ') at offset: {offset}")
                print(f"    Decompressed size will be approximately {len(decompressed_data)} bytes.")
                return offset
        except Exception:
            continue
    
    print("\r    ... scanning (100%)")
    print(f"\n[!] Failed to find a valid offset after scanning the entire file.")
    return None

def main():
    parser = argparse.ArgumentParser(
        description="Visually analyze file entropy and scan for the correct decompression offset.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("input_file", help="Path to the compressed payload file (e.g., payload.bin).")
    args = parser.parse_args()

    # First, generate the visual plot for analysis
    plot_entropy(args.input_file)
    
    # Then, perform the automated full scan
    correct_offset = find_correct_offset(args.input_file)
    
    if correct_offset is not None:
        print("\nNow, run the decompressor with the found offset:")
        print(f"python decompressor.py \"{args.input_file}\" unpacked.exe --offset {correct_offset}")

if __name__ == "__main__":
    main()

