"""
RISC-V Assembler (RV32I subset + basic pseudo-instructions)
Universidad Tecnológica de Pereira - 2025-2


Authors:
- Daniel Alejandro Henao 1114150552
- Juan Camilo Cano 1137059546


Description:
This assembler takes a RISC-V assembly source file (program.asm) and translates it
into binary and hex machine code. It supports:
- RV32I base instructions (R, I, S, B, U, J types)
- Basic pseudo-instructions (e.g., nop, li, mv)
- Data section directives (.word, .half, .byte, .ascii, .asciiz, .string, .space)
- Proper memory alignment for multi-byte data
- Label resolution in both .text and .data sections


Limitations:
- Only RV32I integer instructions
- Pseudo-instructions are partially implemented (e.g., la, call, tail not included)
- Branch/jump offsets limited by instruction format


Usage:
python assembler.py program.asm program.hex program.bin
(expects a file named `program.asm` in the same directory)
"""
import json
import sys

instField = "Instructions.json"

with open(instField, "r") as file:
    insList = json.load(file)


abi_to_num = {
                "zero": 0,
                "ra": 1,
                "sp": 2,
                "gp": 3,
                "tp": 4,
                "t0": 5, "t1": 6, "t2": 7,
                "s0": 8, "fp": 8,
                "s1": 9,
                "a0": 10, "a1": 11, "a2": 12, "a3": 13, "a4": 14, "a5": 15,
                "a6": 16, "a7": 17,
                "s2": 18, "s3": 19, "s4": 20, "s5": 21, "s6": 22, "s7": 23,
                "s8": 24, "s9": 25, "s10": 26, "s11": 27,
                "t3": 28, "t4": 29, "t5": 30, "t6": 31,
}

program_memory = []
memory_labels = {}

def reg_to_num(reg: str) -> int:
    """
    Convert a register name (ABI or xN form) to its numeric index.


    Args:
    reg (str): Register name (e.g., "x5", "a0", "sp")


    Returns:
    int: Register number (0–31)


    Raises:
    ValueError: If the register name is invalid
    """
    reg = reg.strip()
    if reg.startswith("x") and int(reg[1:]) < 32:   # x0..x31
        return int(reg[1:])
    elif reg in abi_to_num:   # ABI name
        return abi_to_num[reg]
    else:
        raise ValueError(f"Unknown register: {reg}")
    

def firstPass(lines):
    """
    First assembler pass.
    - Identifies labels in the .text section
    - Tracks program counter (PC) for each label
    - Ignores .data section directives (they are processed separately)


    Args:
    lines (list[str]): Source lines


    Returns:
    dict: Label -> PC mapping
"""
    labels = {}
    pc = 0
    in_text = False

    for line in lines:
        # Remove comments
        line = line.split("#")[0].strip()
        if not line:
            continue

        # Section switches
        if line.startswith(".data"):
            in_text = False
            continue
        elif line.startswith(".text"):
            in_text = True
            pc = 0  # reset pc at .text start
            continue

        # Inline label (e.g. myvar: .word 15 or loop: addi x1,x1,1)
        if ":" in line:
            label, rest = line.split(":", 1)
            label = label.strip()
            if label in labels:
                raise ValueError(f"Duplicate identifier: {label}")
            if in_text:
                labels[label] = pc # only track PC for .text labels

            rest = rest.strip()
            if not rest:  # pure label line
                continue
            line = rest  # process the remainder as instruction/directive

        # Instructions
        if in_text:
            pc += 4
        # Data: do nothing, handled separately later

    return labels




def to_bin(val, bits):
    """
    Convert signed/unsigned integer to binary string of given width.
    Handles two's complement for negative numbers.
    """
    if val < 0:
        val = (1 << bits) + val
    return format(val & ((1 << bits) - 1), f'0{bits}b')

def assemble(instr, dictlabls, pc):
    """
    Assemble a single RISC-V instruction into a 32-bit binary string.

    Args:
        instr (str): The assembly instruction as a string (may include comments).
                     Example: "addi a0, a1, 10" or "beq a0, a1, loop"
        dictlabls (dict): Mapping from label names to addresses (used for branches/jumps).
        pc (int): Current program counter (instruction address in bytes).

    Returns:
        str or None: The 32-bit binary encoding of the instruction as a string of '0'/'1',
                     or None if the input line was empty/comment only.

    Raises:
        ValueError: If the instruction format is invalid, a label is undefined, or an
                    immediate/offset is out of range.

    Notes:
        - Supports base RV32I instructions: R, I, S, B, U, J types.
        - Implements a subset of pseudo-instructions by recursively expanding them
          (e.g., `nop`, `mv`, `neg`, `ret`, etc.).
        - Comments in the input line (after '#') are automatically ignored.
    """

    # --- Step 1: Strip comments and whitespace ---
    instr = instr.split("#")[0].strip()
    if not instr:
        return None  # ignore empty/comment-only lines

    # --- Step 2: Quick syntax validation for commas ---
    parts = instr.split()
    lparts = len(parts)
    if "," in parts[0]:
        raise ValueError("Syntax error: unexpected comma")
    if "," in parts[lparts - 1]:
        raise ValueError("Syntax error: unexpected comma")
    for i in range(1, lparts - 1):
        if "," not in parts[i]:
            raise ValueError("Syntax error: missing comma")

    # --- Step 3: Normalize instruction tokens (remove commas) ---
    parts = instr.replace(",", "").split()
    lparts = len(parts)
    mnemonic = parts[0]

    # --------------------------------------------------------------------------
    # R-type: add, sub, xor, or, and, sll, srl, sra, slt, sltu
    # --------------------------------------------------------------------------
    if mnemonic in ["add", "sub", "xor", "or", "and", "sll", "srl", "sra", "slt", "sltu"]:
        funct7, funct3, opcode = insList[mnemonic]
        rd = reg_to_num(parts[1])
        rs1 = reg_to_num(parts[2])
        rs2 = reg_to_num(parts[3])
        line = (
            funct7 +
            to_bin(rs2, 5) +
            to_bin(rs1, 5) +
            funct3 +
            to_bin(rd, 5) +
            opcode
        )

    # --------------------------------------------------------------------------
    # I-type arithmetic/logical: addi, xori, ori, andi, slti, sltiu
    # --------------------------------------------------------------------------
    elif mnemonic in ["addi", "xori", "ori", "andi", "slti", "sltiu"]:
        funct3, opcode = insList[mnemonic]
        rd = reg_to_num(parts[1])
        rs = reg_to_num(parts[2])
        imm = int(parts[3], 0)
        if not -2048 <= imm <= 2047:
            raise ValueError(f"Immediate out of range for {mnemonic}: {imm}")
        line = (
            to_bin(imm, 12) +
            to_bin(rs, 5) +
            funct3 +
            to_bin(rd, 5) +
            opcode
        )

    # --------------------------------------------------------------------------
    # Loads: lb, lh, lw, lbu, lhu  (format: lw rd, imm(rs1))
    # --------------------------------------------------------------------------
    elif mnemonic in ["lb", "lh", "lw", "lbu", "lhu"]:
        funct3, opcode = insList[mnemonic]
        rd = reg_to_num(parts[1])
        imm_str, rs1_str = parts[2].split("(")
        imm = int(imm_str, 0)
        if not -2048 <= imm <= 2047:
            raise ValueError(f"Immediate out of range for {mnemonic}: {imm}")
        rs1 = reg_to_num(rs1_str[:-1])  # remove ')'
        line = (
            to_bin(imm, 12) +
            to_bin(rs1, 5) +
            funct3 +
            to_bin(rd, 5) +
            opcode
        )

    # --------------------------------------------------------------------------
    # I-type shifts: slli, srli, srai
    # --------------------------------------------------------------------------
    elif mnemonic in ["slli", "srli", "srai"]:
        funct7, funct3, opcode = insList[mnemonic]
        rd = reg_to_num(parts[1])
        rs1 = reg_to_num(parts[2])
        shamt = int(parts[3], 0)
        line = (
            funct7 +
            to_bin(shamt, 5) +
            to_bin(rs1, 5) +
            funct3 +
            to_bin(rd, 5) +
            opcode
        )

    # --------------------------------------------------------------------------
    # Stores: sb, sh, sw  (format: sw rs2, imm(rs1))
    # --------------------------------------------------------------------------
    elif mnemonic in ["sb", "sh", "sw"]:
        funct3, opcode = insList[mnemonic]
        rs2 = reg_to_num(parts[1])
        imm_str, rs1_str = parts[2].split("(")
        imm = int(imm_str, 0)
        if not -2048 <= imm <= 2047:
            raise ValueError(f"Immediate out of range for {mnemonic}: {imm}")
        rs1 = reg_to_num(rs1_str[:-1])
        imm_bin = to_bin(imm, 12)
        line = (
            imm_bin[:7] +
            to_bin(rs2, 5) +
            to_bin(rs1, 5) +
            funct3 +
            imm_bin[7:] +
            opcode
        )

    # --------------------------------------------------------------------------
    # Branches: beq, bne, blt, bge, bltu, bgeu
    # --------------------------------------------------------------------------
    elif mnemonic in ["beq", "bne", "blt", "bge", "bltu", "bgeu"]:
        funct3, opcode = insList[mnemonic]
        rs1 = reg_to_num(parts[1])
        rs2 = reg_to_num(parts[2])
        label = parts[3]
        if label not in dictlabls:
            raise ValueError(f"Undefined label: {label}")
        target = dictlabls[label]
        offset = target - pc
        if offset % 2 != 0:
            raise ValueError(f"Branch offset not aligned: {offset}")
        imm_bin = to_bin(offset, 13)
        line = (
            imm_bin[0] +        # imm[12]
            imm_bin[2:8] +      # imm[10:5]
            to_bin(rs2, 5) +
            to_bin(rs1, 5) +
            funct3 +
            imm_bin[8:12] +     # imm[4:1]
            imm_bin[1] +        # imm[11]
            opcode
        )

    # --------------------------------------------------------------------------
    # U-type: lui, auipc
    # --------------------------------------------------------------------------
    elif mnemonic in ["lui", "auipc"]:
        opcode = insList[mnemonic][0]
        rd = reg_to_num(parts[1])
        imm = int(parts[2], 0)
        if not 0 <= imm <= 1048575:
            raise ValueError(f"Immediate out of range for {mnemonic}: {imm}")
        line = (
            to_bin(imm, 20) +
            to_bin(rd, 5) +
            opcode
        )

    # --------------------------------------------------------------------------
    # J-type: jal (jal rd, label) or (jal label → expands to jal ra, label)
    # --------------------------------------------------------------------------
    elif mnemonic == "jal":
        opcode = insList[mnemonic][0]
        if lparts == 3:
            rd = reg_to_num(parts[1])
            label = parts[2]
        elif lparts == 2:
            rd = 1  # ra
            label = parts[1]
        else:
            raise ValueError(f"Invalid jal format: {instr}")
        if label not in dictlabls:
            raise ValueError(f"Undefined label: {label}")
        target = dictlabls[label]
        offset = target - pc
        imm_bin = to_bin(offset, 21)
        line = (
            imm_bin[0] +        # imm[20]
            imm_bin[10:20] +    # imm[10:1]
            imm_bin[9] +        # imm[11]
            imm_bin[1:9] +      # imm[19:12]
            to_bin(rd, 5) +
            opcode
        )

    # --------------------------------------------------------------------------
    # I-type Jumps: jalr
    # Supports formats:
    #   jalr rd, rs1, imm
    #   jalr rd, imm(rs1)
    #   jalr rs            (pseudo → jalr x1, rs, 0)
    # --------------------------------------------------------------------------
    elif mnemonic == "jalr":
        funct3, opcode = insList[mnemonic]
        if lparts == 4:
            rd = reg_to_num(parts[1])
            rs1 = reg_to_num(parts[2])
            imm = int(parts[3], 0)
        elif lparts == 3:
            rd = reg_to_num(parts[1])
            imm_str, rs1_str = parts[2].split("(")
            imm = int(imm_str, 0)
            rs1 = reg_to_num(rs1_str[:-1])
        elif lparts == 2:
            rd = 1
            rs1 = reg_to_num(parts[1])
            imm = 0
        else:
            raise ValueError(f"Invalid jalr format: {instr}")
        line = (
            to_bin(imm, 12) +
            to_bin(rs1, 5) +
            funct3 +
            to_bin(rd, 5) +
            opcode
        )

    # --------------------------------------------------------------------------
    # Pseudo-instructions (expanded recursively into base instructions)
    # --------------------------------------------------------------------------
    elif mnemonic == "nop":
        return assemble("addi x0, x0, 0", dictlabls, pc)
    elif mnemonic == "mv":
        return assemble(f"addi {parts[1]}, {parts[2]}, 0", dictlabls, pc)
    elif mnemonic == "not":
        return assemble(f"xori {parts[1]}, {parts[2]}, -1", dictlabls, pc)
    elif mnemonic == "neg":
        return assemble(f"sub {parts[1]}, x0, {parts[2]}", dictlabls, pc)
    elif mnemonic == "seqz":
        return assemble(f"sltiu {parts[1]}, {parts[2]}, 1", dictlabls, pc)
    elif mnemonic == "snez":
        return assemble(f"sltu {parts[1]}, x0, {parts[2]}", dictlabls, pc)
    elif mnemonic == "sltz":
        return assemble(f"slt {parts[1]}, {parts[2]}, 0", dictlabls, pc)
    elif mnemonic == "sgtz":
        return assemble(f"slt {parts[1]}, 0, {parts[2]}", dictlabls, pc)
    elif mnemonic == "beqz":
        return assemble(f"beq {parts[1]}, x0, {parts[2]}", dictlabls, pc)
    elif mnemonic == "bnez":
        return assemble(f"bne {parts[1]}, x0, {parts[2]}", dictlabls, pc)
    elif mnemonic == "blez":
        return assemble(f"bge x0, {parts[1]}, {parts[2]}", dictlabls, pc)
    elif mnemonic == "bgez":
        return assemble(f"bge {parts[1]}, x0, {parts[2]}", dictlabls, pc)
    elif mnemonic == "bltz":
        return assemble(f"blt {parts[1]}, x0, {parts[2]}", dictlabls, pc)
    elif mnemonic == "bgtz":
        return assemble(f"blt x0, {parts[1]}, {parts[2]}", dictlabls, pc)
    elif mnemonic == "bgt":
        return assemble(f"blt {parts[2]}, {parts[1]}, {parts[3]}", dictlabls, pc)
    elif mnemonic == "ble":
        return assemble(f"bge {parts[2]}, {parts[1]}, {parts[3]}", dictlabls, pc)
    elif mnemonic == "bgtu":
        return assemble(f"bltu {parts[2]}, {parts[1]}, {parts[3]}", dictlabls, pc)
    elif mnemonic == "bleu":
        return assemble(f"bgeu {parts[2]}, {parts[1]}, {parts[3]}", dictlabls, pc)
    elif mnemonic == "j":
        return assemble(f"jal x0, {parts[1]}", dictlabls, pc)
    elif mnemonic == "jr":
        return assemble(f"jalr x0, {parts[1]}, 0", dictlabls, pc)
    elif mnemonic == "ret":
        return assemble("jalr x0, x1, 0", dictlabls, pc)

    # --------------------------------------------------------------------------
    # System instructions
    # --------------------------------------------------------------------------
    elif mnemonic == "ecall":
        line = "00000000000000000000000001110011"
    elif mnemonic == "ebreak":
        line = "00000000000100000000000001110011"
    else:
        raise ValueError(f"Unsupported instruction: {mnemonic}")

    return line



def align(program_memory, current_address, alignment):
    """Pad with 0s until current_address is a multiple of alignment."""
    while current_address % alignment != 0:
        program_memory.append("00000000")
        current_address += 1
    return current_address


def datafunc(instr, program_memory, data_labels, current_address):
    """
    Process a data directive (.word, .half, .byte, .ascii, .asciiz, .string, .space).
    Updates program memory and assigns addresses to labels.


    Args:
    instr (str): A single line from the .data section
    program_memory (list[str]): List of binary strings (8 bits each)
    data_labels (dict): Label -> memory address mapping
    current_address (int): Current memory pointer


    Returns:
    int: Updated memory address after processing this directive
"""
    instr = instr.split("#")[0].strip()  # strip comments
    if not instr:
        return None 
    parts = instr.replace(":", "").split(maxsplit=2)
    label, mnemonic = parts[0], parts[1]

    # Save label -> starting address
    data_labels[label] = current_address

    # Handle possible multiple values: .word 1,2,3
    values = parts[2].split(",")

    for value in values:
        value = value.strip()

        if mnemonic == ".word":
            current_address = align(program_memory, current_address, 4)
            val = int(value, 0)
            for i in range(4):
                byte = (val >> (8 * i)) & 0xFF
                program_memory.append(f"{byte:08b}")
            current_address += 4

        elif mnemonic == ".half":
            current_address = align(program_memory, current_address, 2)
            val = int(value, 0)
            for i in range(2):
                byte = (val >> (8 * i)) & 0xFF
                program_memory.append(f"{byte:08b}")
            current_address += 2

        elif mnemonic == ".byte":
            val = int(value, 0)
            program_memory.append(f"{val & 0xFF:08b}")
            current_address += 1

        elif mnemonic == ".ascii":
            string = value.strip('"')
            for ch in string:
                program_memory.append(f"{ord(ch):08b}")
                current_address += 1

        elif mnemonic in [".asciiz", ".string"]:
            string = value.strip('"')
            for ch in string:
                program_memory.append(f"{ord(ch):08b}")
                current_address += 1
            program_memory.append("00000000")  # null terminator
            current_address += 1

        elif mnemonic == ".space":
            for i in range(int(value)):
                program_memory.append("00000000")
            current_address += int(value)

        else:
            raise ValueError(f"Unknown data directive: {mnemonic}")

    return current_address


def main():
    if len(sys.argv) != 4:
        print("Usage: python assembler.py program.asm program.hex program.bin")
        sys.exit(1)

    asm_file, hex_file, bin_file = sys.argv[1], sys.argv[2], sys.argv[3]

    # Read source program
    with open(asm_file, "r") as f:
        lines = [line.strip() for line in f if line.strip()]

    # First pass: collect labels
    labels = firstPass(lines)

    in_data = False
    in_text = True
    pc = 0
    current_address = 0
    binary_output = []

    for line in lines:
        line = line.split("#")[0].strip()
        if not line:
            continue
        if line.startswith(".data"):
            in_data, in_text = True, False
            continue
        elif line.startswith(".text"):
            in_data, in_text = False, True
            continue

        if in_data:
            current_address = datafunc(line, program_memory, memory_labels, current_address)

        elif in_text:
            if line.endswith(":"):
                continue
            binary = assemble(line, labels, pc)
            binary_output.append(binary)
            pc += 4

    # ===== Write outputs =====
    with open(bin_file, "w") as bf:
        # Write binary instructions
        for b in binary_output:
            bf.write(b + "\n")
        # Write binary data
        for b in program_memory:
            bf.write(b + "\n")

    with open(hex_file, "w") as hf:
        # Convert binary to hex
        for b in binary_output:
            hf.write(f"{int(b, 2):08x}\n")
        for b in program_memory:
            hf.write(f"{int(b, 2):02x}\n")

    print(f"Assembly complete. Output -> {hex_file}, {bin_file}")


if __name__ == "__main__":
    main()