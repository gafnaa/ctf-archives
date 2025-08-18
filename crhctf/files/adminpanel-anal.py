# Skrip ini menggunakan pyelftools dan capstone untuk menganalisis dan membongkar file ELF.
# Untuk menginstal pustaka yang diperlukan, gunakan pip:
# pip install pyelftools capstone

import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

def disassemble_from_address(filename, target_address, size=100):
    """
    Membongkar sejumlah 'size' byte kode dari alamat target dalam file ELF.
    """
    try:
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)

            # Temukan bagian .text
            text_section = elffile.get_section_by_name('.text')
            if not text_section:
                print("\n[-] Bagian .text tidak ditemukan.")
                return

            code = text_section.data()
            section_addr = text_section['sh_addr']
            
            # Hitung offset dalam data bagian .text
            offset = target_address - section_addr
            
            if 0 <= offset < len(code):
                # Ambil potongan kode untuk dibongkar
                code_chunk = code[offset : offset + size]
                
                print(f"\n[*] Membongkar {size} byte dari alamat 0x{target_address:x}:")
                
                # Inisialisasi Capstone disassembler untuk x86-64
                md = Cs(CS_ARCH_X86, CS_MODE_64)
                
                # Bongkar kode dan cetak instruksi
                for i in md.disasm(code_chunk, target_address):
                    print(f"  0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
            else:
                print(f"[-] Alamat target 0x{target_address:x} tidak ditemukan di dalam bagian .text.")

    except FileNotFoundError:
        print(f"[-] Error: File '{filename}' tidak ditemukan.")
    except ImportError:
        print("[-] Error: Capstone atau pyelftools tidak terinstal.")
        print("[-] Silakan instal dengan: pip install pyelftools capstone")
    except Exception as e:
        print(f"[-] Terjadi kesalahan: {e}")

if __name__ == '__main__':
    FILENAME = 'adminpanel'
    # Alamat fungsi yang menarik dari Ghidra
    FUNCTION_ADDRESS = 0x00401a56 
    
    # Ganti 'adminpanel' dengan path file Anda jika tidak berada di direktori yang sama.
    disassemble_from_address(FILENAME, FUNCTION_ADDRESS)
