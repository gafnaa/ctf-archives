import pefile
import sys

def extract_boot_section(exe_path, output_path):
    """
    Extracts the .boot section from a PE file, which likely contains
    the compressed payload in this packed executable.

    Args:
        exe_path (str): The path to the input executable file.
        output_path (str): The path where the extracted section will be saved.
    """
    try:
        pe = pefile.PE(exe_path)
    except pefile.PEFormatError as e:
        print(f"Error: Not a valid PE file or file not found - {e}")
        return
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return

    boot_section = None
    # Packers often use non-standard section names. '.boot' was in your file.
    for section in pe.sections:
        # Section names are byte strings, so we decode them for comparison
        if section.Name.decode().strip('\x00') == '.boot':
            boot_section = section
            break
            
    if boot_section:
        print(f"[*] Found '.boot' section at virtual address 0x{boot_section.VirtualAddress:X}")
        print(f"    Size: {boot_section.SizeOfRawData} bytes")
        
        data = boot_section.get_data()
        
        with open(output_path, 'wb') as f:
            f.write(data)
            
        print(f"[+] Successfully extracted section to '{output_path}'")
    else:
        print("Error: '.boot' section not found in the executable.")
        print("The compressed data might be in another section like '.themida'.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python payload_extractor.py <path_to_exe> <output_payload_file>")
        print("Example: python payload_extractor.py Packs.exe payload.bin")
        sys.exit(1)
        
    exe_file = sys.argv[1]
    output_file = sys.argv[2]
    
    extract_boot_section(exe_file, output_file)
