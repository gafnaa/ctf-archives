def decrypt_tusligt(filepath="tusligt.bin"):
    """
    Decrypts the tusligt.bin file by simulating the virtual machine
    described in the decompiled C code.
    """
    try:
        with open(filepath, "rb") as f:
            ptr = bytearray(f.read())
    except FileNotFoundError:
        print(f"Error: {filepath} not found!")
        return

    size = len(ptr)
    regs = [0] * 4
    stack = []
    instruction_pointer = 0
    zero_flag = 0

    output = []

    while instruction_pointer < size:
        opcode = ptr[instruction_pointer]
        instruction_pointer += 1

        if opcode == 0xFF:  # HALT
            break
        elif opcode == 0x94:  # ADD reg, reg
            reg1 = ptr[instruction_pointer]
            instruction_pointer += 1
            reg2 = ptr[instruction_pointer]
            instruction_pointer += 1
            regs[reg1] = (regs[reg1] + regs[reg2]) & 0xFF
        elif opcode == 0x93:  # POP reg
            reg = ptr[instruction_pointer]
            instruction_pointer += 1
            if stack:
                regs[reg] = stack.pop()
        elif opcode == 0x8B:  # OUT reg
            reg = ptr[instruction_pointer]
            instruction_pointer += 1
            output.append(chr(regs[reg]))
        elif opcode == 0x76:  # PUSH reg
            reg = ptr[instruction_pointer]
            instruction_pointer += 1
            stack.append(regs[reg])
        elif opcode == 0x6A:  # IN reg
            # Since we don't have interactive input, we'll need to
            # analyze the logic or provide a dummy value if needed.
            # For now, let's assume it's not critical for decryption.
            reg = ptr[instruction_pointer]
            instruction_pointer += 1
            # regs[reg] = ord(input("Enter a character: ")[0])
            pass # Skipping for non-interactive decryption
        elif opcode == 0x61:  # PUSH imm
            val = ptr[instruction_pointer]
            instruction_pointer += 1
            stack.append(val)
        elif opcode == 0x54:  # MOV reg, imm
            reg = ptr[instruction_pointer]
            instruction_pointer += 1
            val = ptr[instruction_pointer]
            instruction_pointer += 1
            regs[reg] = val
        elif opcode == 0x43:  # SUB reg, reg
            reg1 = ptr[instruction_pointer]
            instruction_pointer += 1
            reg2 = ptr[instruction_pointer]
            instruction_pointer += 1
            regs[reg1] = (regs[reg1] - regs[reg2]) & 0xFF
        elif opcode == 0x39:  # JZ addr
            addr = int.from_bytes(ptr[instruction_pointer:instruction_pointer+2], 'little')
            instruction_pointer += 2
            if zero_flag:
                instruction_pointer = addr
        elif opcode == 0x29:  # CMP reg, reg
            reg1 = ptr[instruction_pointer]
            instruction_pointer += 1
            reg2 = ptr[instruction_pointer]
            instruction_pointer += 1
            zero_flag = 1 if regs[reg1] == regs[reg2] else 0
        elif opcode == 0x33:  # XOR reg, reg
            reg1 = ptr[instruction_pointer]
            instruction_pointer += 1
            reg2 = ptr[instruction_pointer]
            instruction_pointer += 1
            regs[reg1] ^= regs[reg2]
        else:
            print(f"Error: Unknown instruction {opcode:02X} at address {instruction_pointer - 1:04X}")
            break

    print("Decrypted Output:")
    print("".join(output))

if __name__ == "__main__":
    decrypt_tusligt()
