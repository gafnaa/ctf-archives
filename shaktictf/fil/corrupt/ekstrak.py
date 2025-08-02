import sys
import re

def extract_data(input_file_path, output_file_path):
    """
    Parses the output of pdf-parser and extracts the data hidden in comments.

    Args:
        input_file_path (str): The path to the text file containing the pdf-parser output.
        output_file_path (str): The path where the extracted binary data will be saved.
    """
    extracted_bytes = b''

    # Regex to find the content inside: PDF Comment '%...'\n
    # This pattern captures the literal string content between the single quotes.
    pattern = re.compile(r"PDF Comment '(%.*?)'\n")

    try:
        with open(input_file_path, 'r', encoding='utf-8', errors='ignore') as f_in:
            content = f_in.read()
            matches = pattern.findall(content)

            for match in matches:
                # The matched string has escapes like \\xHH.
                # We convert it to the bytes it represents.
                # The 'latin-1' -> 'unicode_escape' -> 'latin-1' chain is a robust way
                # to handle string literals containing hex escapes.
                decoded_bytes = match.encode('latin-1').decode('unicode_escape').encode('latin-1')
                extracted_bytes += decoded_bytes

        with open(output_file_path, 'wb') as f_out:
            f_out.write(extracted_bytes)

        print(f"✅ Successfully extracted {len(extracted_bytes)} bytes to '{output_file_path}'")

    except FileNotFoundError:
        print(f"❌ Error: Input file '{input_file_path}' not found.", file=sys.stderr)
    except Exception as e:
        print(f"❌ An error occurred: {e}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <input_log_file> <output_binary_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    extract_data(input_file, output_file)
