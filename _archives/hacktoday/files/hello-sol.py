# This Python script acts as a "solver" or "decryptor" for the C code's
# obfuscation technique. It uses CPU emulation to find and execute the
# hidden signal handler logic from a compiled binary.
#
# HOW IT WORKS:
# 1. It takes a compiled STATIC ELF binary as input.
# 2. It parses the binary's symbol table to find the memory address of the
#    hidden function ('handle_sigill').
# 3. It uses the 'unicorn' framework to create a virtual x86-64 CPU and memory.
# 4. It loads the program's executable segments (code, data, etc.) into the
#    emulator's memory, mimicking how an OS would load a program.
# 5. It hooks system calls. The C code's `printf` and `exit` functions
#    ultimately make system calls to the OS kernel. We intercept these calls
#    to see what the program is trying to do.
# 6. It sets the emulator's instruction pointer (RIP) to the start of the
#    'handle_sigill' function and begins execution.
# 7. When the emulated code calls `printf`, our hook catches the underlying
#    'write' syscall, reads the message from the emulator's memory, and
#    prints it to our console.
# 8. When the emulated code calls `exit`, our hook catches the 'exit'
#    syscall and cleanly stops the emulation.

import argparse
from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.x86_const import *

# --- C Source Code to be Compiled ---
# You must compile this C code first. Save it as `obfuscated.c` and compile STATICALLY with:
# gcc -no-pie -static -o obfuscated_program_static obfuscated.c
#
# The `-static` flag is crucial. It includes all library code in the executable,
# preventing errors from calls to unloaded shared libraries during emulation.
C_CODE = """
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

// This is the hidden function we want to find and execute.
void handle_sigill(int signum) {
    printf("Secret message revealed!\\n");
    printf("The signal handler was the key.\\n");
    exit(0);
}

// Macro to cause an illegal instruction.
#define BUG() __asm__("ud2")

int main() {
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = handle_sigill;
    sigaction(SIGILL, &act, NULL);
    printf("Hello guys!\\n");
    BUG();
    return 0;
}
"""

# --- Python Solver Script ---

# A typical base address for non-PIE executables.
STACK_ADDRESS = 0x70000000
STACK_SIZE = 1024 * 1024 # 1MB stack

def find_symbol_address(elf_path, symbol_name):
    """Parses an ELF file to find the virtual address of a symbol."""
    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        if not symtab:
            print(f"Error: Could not find .symtab section in {elf_path}.")
            print("Did you forget to compile the C code?")
            return None

        symbols = symtab.get_symbol_by_name(symbol_name)
        if symbols:
            # The value of the symbol is its virtual address
            return symbols[0].entry['st_value']
    return None

def hook_syscall(uc, user_data):
    """
    This function is called when the emulator encounters a 'syscall' instruction.
    We use it to emulate the 'write' and 'exit' syscalls.
    """
    rax = uc.reg_read(UC_X86_REG_RAX)

    # Syscall number for 'write' on x86-64 is 1
    if rax == 1:
        # rdi = file descriptor (1 for stdout)
        # rsi = pointer to the string buffer
        # rdx = length of the string
        rdi = uc.reg_read(UC_X86_REG_RDI)
        rsi = uc.reg_read(UC_X86_REG_RSI)
        rdx = uc.reg_read(UC_X86_REG_RDX)

        if rdi == 1: # Check if writing to stdout
            try:
                # Read the string from the emulator's memory
                data = uc.mem_read(rsi, rdx)
                print(f"[+] Intercepted 'write' syscall: {data.decode('utf-8')}", end='')
            except Exception as e:
                print(f"[-] Error reading memory for write syscall: {e}")
        # We don't need to return a value for this simple emulation.

    # Syscall number for 'exit' on x86-64 is 60
    elif rax == 60:
        rdi = uc.reg_read(UC_X86_REG_RDI)
        print(f"\n[+] Intercepted 'exit' syscall with code {rdi}. Halting emulation.")
        uc.emu_stop()
    else:
        print(f"[-] Unhandled syscall: {rax}")
        uc.emu_stop()

def main(elf_path):
    """Main function to run the emulation."""
    print(f"[*] Analyzing '{elf_path}'...")

    # 1. Find the address of the hidden function
    handler_address = find_symbol_address(elf_path, 'handle_sigill')
    if not handler_address:
        print(f"[-] Could not find address for 'handle_sigill'. Exiting.")
        return

    print(f"[+] Found 'handle_sigill' at virtual address: {hex(handler_address)}")

    try:
        # 2. Initialize the Unicorn emulator for x86 64-bit
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        # 3. Load the executable's segments into the emulator's memory
        with open(elf_path, 'rb') as f:
            elf = ELFFile(f)
            
            # Set a high-level end address for the emulation.
            # We just need to ensure it's beyond any code we'll execute.
            emulation_end_addr = 0x800000 

            # Iterate over ELF segments and map them into emulator memory
            print("[*] Loading program segments into emulator memory...")
            for segment in elf.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    vaddr = segment['p_vaddr']
                    mem_size = segment['p_memsz']
                    file_size = segment['p_filesz']
                    permissions = segment['p_flags'] # PF_X, PF_W, PF_R
                    data = segment.data()

                    # Align address and size to page boundaries for mem_map
                    align = 0x1000 # 4KB page size
                    map_addr = vaddr & ~(align - 1)
                    map_size = (vaddr + mem_size - map_addr + align - 1) & ~(align - 1)

                    # Convert ELF permissions to Unicorn permissions
                    uc_perms = 0
                    if permissions & 1: uc_perms |= UC_PROT_EXEC
                    if permissions & 2: uc_perms |= UC_PROT_WRITE
                    if permissions & 4: uc_perms |= UC_PROT_READ

                    print(f"    -> Mapping segment at {hex(map_addr)} with size {hex(map_size)} and perms {uc_perms}")
                    mu.mem_map(map_addr, map_size, perms=uc_perms)
                    
                    if file_size > 0:
                        mu.mem_write(vaddr, data)

        # Map memory for the stack
        mu.mem_map(STACK_ADDRESS, STACK_SIZE)
        mu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + STACK_SIZE - 1)
        print(f"[*] Mapped stack at {hex(STACK_ADDRESS)}")

        # 4. Add the syscall hook
        mu.hook_add(UC_HOOK_INSN, hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
        print("[*] Syscall hook installed.")
        
        # 5. Start emulation at the beginning of our target function
        print("\n--- Emulating hidden function ---")
        mu.emu_start(handler_address, emulation_end_addr)
        print("--- Emulation finished ---\n")

    except UcError as e:
        print(f"[-] UNICORN ERROR: {e}")
    except FileNotFoundError:
        print(f"[-] Error: File not found at '{elf_path}'")
        print("[-] Please re-compile the C code first using:")
        print("[-] gcc -no-pie -static -o obfuscated_program_static obfuscated.c")


if __name__ == '__main__':
    # Setup to run from the command line
    # To run:
    # 1. Save the C code above as `obfuscated.c`
    # 2. Compile it statically: `gcc -no-pie -static -o obfuscated_program_static obfuscated.c`
    # 3. Install dependencies: `pip install unicorn pyelftools`
    # 4. Run this script: `python your_script_name.py obfuscated_program_static`
    
    parser = argparse.ArgumentParser(description="Find and emulate a hidden function in a static ELF binary.")
    parser.add_argument("elf_path", help="Path to the compiled static ELF binary (e.g., 'obfuscated_program_static')")
    args = parser.parse_args()
    
    main(args.elf_path)
