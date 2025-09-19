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
        line = line.split("#")[0].strip()
        if not line:
            continue
        #For stripping white lines AND comments

        if line.endswith(":"):
            label = line[:-1]
            if label in labels:
                raise ValueError(f"Invalid, duplicate identifier: {label}")
            labels[label] = pc
        else:
            pc += 4

    return labels

def to_bin(val, bits):
    if val < 0:
        val = (1 << bits) + val
    return format(val & ((1 << bits) - 1), f'0{bits}b')

def assemble(instr, dictlabls, pc):
    parts = instr.replace(",", "").split()
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
        imm = offset >> 1
        imm_bin = to_bin(imm, 13)
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
            to_bin(imm, 20) +
            to_bin(rd, 5) +
            opcode
        )
    
    elif mnemonic in ["jal"]:  # JType
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
    
    elif mnemonic in ["jalr"]:  # IType jalr #CORREGIR
        funct3, opcode = insList[mnemonic]
        rd = reg_to_num(parts[1])
        rs1 = reg_to_num(parts[2])
        imm = int(parts[3], 0)
        line = (
            to_bin(imm, 12) +
            to_bin(rs1, 5) +
            funct3 +
            to_bin(rd, 5) +
            opcode
        )

    elif mnemonic == "ecall":
        line = "00000000000000000000000001110011"

    elif mnemonic == "ebreak":
        line = "00000000000100000000000001110011"

    else:
        raise ValueError(f"Unsupported instruction: {mnemonic}")

    return line




















# Example usage


with open("program.asm", "r") as f:
    lines = [line.strip() for line in f if line.strip()]

labels = firstPass(lines)
print("Labels:", labels)

# Assemble
pc = 0
for line in lines:
    if line.endswith(":"): 
        continue
    binary = assemble(line, labels,pc)
    print(binary)
    pc += 4

