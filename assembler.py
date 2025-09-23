import json

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
    reg = reg.strip()
    if reg.startswith("x"):   # x0..x31
        return int(reg[1:])
    elif reg in abi_to_num:   # ABI name
        return abi_to_num[reg]
    else:
        raise ValueError(f"Unknown register: {reg}")
    

def firstPass(lines):
    labels = {}
    pc = 0

    for line in lines:
        line = line.split("#")[0].strip()  # Remove comments
        if not line:
            continue
        
        if len(line.split("#")[0].strip().split()) != 1 and "," not in line: #Label with spaces, not allowed
            raise ValueError(f"Invalid syntax: {line}, not space allowed in labels")

        if line.endswith(":"):  # label
            label = line[:-1]
            if label in labels:
                raise ValueError(f"Invalid, duplicate identifier: {label}")
            labels[label] = pc
        elif line.startswith(".word") or line.startswith(".half") or line.startswith(".byte") or line.startswith(".ascii") or line.startswith(".asciiz"):
            continue
        else:
            pc += 4

    return labels



def to_bin(val, bits):
    if val < 0:
        val = (1 << bits) + val
    return format(val & ((1 << bits) - 1), f'0{bits}b')

def assemble(instr, dictlabls, pc):

    parts = instr.split()
    lparts = len(parts)
    if "," in parts[0]:
        raise ValueError("Syntax error: unexpected comma")
    if "," in parts[lparts - 1]:
        raise ValueError("Syntax error: unexpected comma")
    for i in range(1, lparts - 1):
        if "," not in parts[i]:
            raise ValueError("Syntax error: missing comma")

    parts = instr.replace(",", "").split()
    lparts = len(parts)
    mnemonic = parts[0]

    if mnemonic in ["add", "sub", "xor", "or", "and", "sll", "srl", "sra", "slt", "sltu"]:  # RType
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

    elif mnemonic in ["addi", "xori", "ori", "andi", "slti", "sltiu"]:  # IType
        funct3, opcode = insList[mnemonic]
        rd = reg_to_num(parts[1])
        rs = reg_to_num(parts[2])
        imm = int(parts[3], 0)
        line = (
            to_bin(imm, 12) +
            to_bin(rs, 5) +
            funct3 +
            to_bin(rd, 5) +
            opcode
        )

    elif mnemonic in ["lb", "lh", "lw", "lbu", "lhu"]:  # Load IType
        funct3, opcode = insList[mnemonic]
        rd = reg_to_num(parts[1])
        imm_str, rs1_str = parts[2].split("(")
        imm = int(imm_str, 0)
        rs1 = reg_to_num(rs1_str[:-1])  # strip ")"
        line = (
            to_bin(imm, 12) + " - " +
            to_bin(rs1, 5) + " - " +
            funct3 + " - " +
            to_bin(rd, 5) + " - " +
            opcode
        )

    elif mnemonic in ["slli", "srli", "srai"]:  # IShiftType
        funct3, opcode = insList[mnemonic]
        rd = reg_to_num(parts[1])
        rs1 = reg_to_num(parts[2])
        shamt = int(parts[3], 0)
        line = (
            "0000000" +   # funct7 for shifts is handled in JSON normally
            to_bin(shamt, 5) +
            to_bin(rs1, 5) +
            funct3 +
            to_bin(rd, 5) +
            opcode
        )

    elif mnemonic in ["sb", "sh", "sw"]:  # SType
        funct3, opcode = insList[mnemonic]
        rs2 = reg_to_num(parts[1])
        imm_str, rs1_str = parts[2].split("(")
        imm = int(imm_str, 0)
        rs1 = reg_to_num(rs1_str[:-1])  # strip ")"
        imm_bin = to_bin(imm, 12)
        imm_hi = imm_bin[:7]
        imm_lo = imm_bin[7:]
        line = (
            imm_hi +
            to_bin(rs2, 5) +
            to_bin(rs1, 5) +
            funct3 +
            imm_lo +
            opcode
        )

    elif mnemonic in ["beq", "bne", "blt", "bge", "bltu", "bgeu"]:  # BType
        funct3, opcode = insList[mnemonic]
        rs1 = reg_to_num(parts[1])
        rs2 = reg_to_num(parts[2])
        label = parts[3]
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


    elif mnemonic in ["lui", "auipc"]:  # UType
        opcode = insList[mnemonic][0]
        rd = reg_to_num(parts[1])
        imm = int(parts[2], 0)
        line = (
            to_bin(imm, 20)+
            to_bin(rd, 5) +
            opcode
        )
    
    elif mnemonic in ["jal"] and parts[1] in abi_to_num:  # JType
        opcode = insList[mnemonic][0]
        rd = reg_to_num(parts[1])
        label = parts[2]
        target = dictlabls[label]
        offset = target - pc
        imm = offset >> 1
        imm_bin = to_bin(imm, 21)
        line = (
            imm_bin[0] +        
            imm_bin[10:20] +    
            imm_bin[9] +        
            imm_bin[1:9] +      
            to_bin(rd, 5) +
            opcode
        )
    
    elif mnemonic in ["jalr"] and lparts != 2:  # IType jalr
        funct3, opcode = insList[mnemonic]
        rd = reg_to_num(parts[1])
        imm_str, rs1_str = parts[2].split("(")
        imm = int(imm_str, 0)
        rs1 = reg_to_num(rs1_str[:-1])  # strip ")"
        line = (
            to_bin(imm, 12) +
            to_bin(rs1, 5) +
            funct3 +
            to_bin(rd, 5) +
            opcode
        )

    # Pseudo-instructions, not la, l{b,h,w}, s{b,h,w}, call offset nor tail offset
    elif mnemonic == "nop":
        return assemble("addi x0, x0, 0", dictlabls, pc)
    
    elif mnemonic == "li":
        rd = parts[1]
        imm = int(parts[2], 0)
        if -2048 <= imm <= 2047:
            return assemble(f"addi {rd}, x0, {imm}", dictlabls, pc)
        elif -2147483648 <= imm <= 2147483647:
            upper = (imm + (1 << 11)) >> 12
            lower = imm - (upper << 12)
            return assemble(f"addi {rd}, {rd}, {lower}", dictlabls, pc + 4)
        else:
            raise ValueError(f"Immediate out of range for li: {imm}")
    
    elif mnemonic == "mv":
        rd = parts[1]
        rs = parts[2]
        return assemble(f"addi {rd}, {rs}, 0", dictlabls, pc)
    
    elif mnemonic == "not":
        rd = parts[1]
        rs = parts[2]
        return assemble(f"xori {rd}, {rs}, -1", dictlabls, pc)
    
    elif mnemonic == "neg":
        rd = parts[1]
        rs = parts[2]
        return assemble(f"sub {rd}, x0, {rs}", dictlabls, pc)
    
    elif mnemonic == "seqz":
        rd = parts[1]
        rs = parts[2]
        return assemble(f"sltiu {rd}, {rs}, 1", dictlabls, pc)
    
    elif mnemonic == "snez":
        rd = parts[1]
        rs = parts[2]
        return assemble(f"sltu {rd}, x0, {rs}", dictlabls, pc)
    
    elif mnemonic == "sltz":
        rd = parts[1]
        rs = parts[2]
        return assemble(f"slt {rd}, {rs}, 0", dictlabls, pc)
    
    elif mnemonic == "sgtz":
        rd = parts[1]
        rs = parts[2]
        return assemble(f"slt {rd}, 0, {rs}", dictlabls, pc)
    
    elif mnemonic == "beqz":
        rs = parts[1]
        label = parts[2]
        return assemble(f"beq {rs}, x0, {label}", dictlabls, pc)
    
    elif mnemonic == "bnez":
        rs = parts[1]
        label = parts[2]
        return assemble(f"bne {rs}, x0, {label}", dictlabls, pc)
    
    elif mnemonic == "blez":
        rs = parts[1]
        label = parts[2]
        return assemble(f"bge x0, {rs}, {label}", dictlabls, pc)
    
    elif mnemonic == "bgez":
        rs = parts[1]
        label = parts[2]
        return assemble(f"bge {rs}, x0, {label}", dictlabls, pc)
    
    elif mnemonic == "bltz":
        rs = parts[1]
        label = parts[2]
        return assemble(f"blt {rs}, x0, {label}", dictlabls, pc)
    
    elif mnemonic == "bgtz":
        rs = parts[1]
        label = parts[2]
        return assemble(f"blt x0, {rs}, {label}", dictlabls, pc)
    
    elif mnemonic == "bgt":
        rs1 = parts[1]
        rs2 = parts[2]
        label = parts[3]
        return assemble(f"blt {rs2}, {rs1}, {label}", dictlabls, pc)
    
    elif mnemonic == "ble":
        rs1 = parts[1]
        rs2 = parts[2]
        label = parts[3]
        return assemble(f"bge {rs2}, {rs1}, {label}", dictlabls, pc)
    
    elif mnemonic == "bgtu":
        rs1 = parts[1]
        rs2 = parts[2]
        label = parts[3]
        return assemble(f"bltu {rs2}, {rs1}, {label}", dictlabls, pc)
    
    elif mnemonic == "bleu":
        rs1 = parts[1]
        rs2 = parts[2]
        label = parts[3]
        return assemble(f"bgeu {rs2}, {rs1}, {label}", dictlabls, pc)
    
    elif mnemonic == "j":
        label = parts[1]
        return assemble(f"jal x0, {label}", dictlabls, pc)
    
    elif mnemonic == "jal" and parts[1] not in abi_to_num and parts[1] in dictlabls:
        rs = parts[1]
        return assemble(f"jalr x0, {label}", dictlabls, pc)
    
    elif mnemonic == "jr":
        rs = parts[1]
        return assemble(f"jalr x0, {rs}, 0", dictlabls, pc)
    
    elif mnemonic == "jalr" and parts[1] in abi_to_num and lparts == 2:
        rs = parts[1]
        return assemble(f"jalr x1, {rs}, 0", dictlabls, pc)
    
    elif mnemonic == "ret":
        return assemble("jalr x0, x1, 0", dictlabls, pc)

    elif mnemonic == "ecall":
        line = "00000000000000000000000001110011"

    elif mnemonic == "ebreak":
        line = "00000000000100000000000001110011"

    else:
        raise ValueError(f"Unsupported instruction: {mnemonic}")

    return line


def datafunc(instr, program_memory, data_labels, current_address):
    parts = instr.replace(":", "").split(maxsplit=2)
    label, mnemonic = parts[0], parts[1]

    # Save label -> starting address
    data_labels[label] = current_address

    # Handle possible multiple values: .word 1,2,3
    values = parts[2].split(",")

    for value in values:
        value = value.strip()

        if mnemonic == ".word":
            val = int(value, 0)
            for i in range(4):
                byte = (val >> (8 * i)) & 0xFF
                program_memory.append(f"{byte:08b}")
            current_address += 4

        elif mnemonic == ".dword":
            val = int(value, 0)
            for i in range(8):
                byte = (val >> (8 * i)) & 0xFF
                program_memory.append(f"{byte:08b}")
            current_address += 8

        elif mnemonic == ".half":
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

        elif mnemonic == ".asciiz":
            string = value.strip('"')
            for ch in string:
                program_memory.append(f"{ord(ch):08b}")
                current_address += 1
            program_memory.append("00000000")  # null terminator
            current_address += 1
        elif mnemonic == ".space":
            for i in range(int(value)):
                byte = 0x0
                program_memory.append(f"{byte:08b}")
            current_address += int(value)

        else:
            raise ValueError(f"Unknown data directive: {mnemonic}")

    return current_address

with open("program.asm", "r") as f:
    lines = [line.strip() for line in f if line.strip()]

labels = firstPass(lines)

print("Labels:", labels)

# Assemble
in_data = False
in_text = True
pc = 0
current_address = 0

for line in lines:
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
        print(binary)


        pc += 4
print(memory_labels)
for byte in program_memory:
    print(byte)