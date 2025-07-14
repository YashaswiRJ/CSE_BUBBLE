import re

registers = {
    "$zero": 0, "$at": 1,
    "$v0": 2, "$v1": 3,
    "$a0": 4, "$a1": 5, "$a2": 6, "$a3": 7,
    "$t0": 8, "$t1": 9, "$t2": 10, "$t3": 11, "$t4": 12, "$t5": 13, "$t6": 14, "$t7": 15,
    "$s0": 16, "$s1": 17, "$s2": 18, "$s3": 19, "$s4": 20, "$s5": 21, "$s6": 22, "$s7": 23,
    "$t8": 24, "$t9": 25,
    "$k0": 26, "$k1": 27,
    "$gp": 28, "$sp": 29, "$fp": 30, "$ra": 31
}

opcode_table = {
    'add':  '000000', 'sub':  '000000', 'and':  '000000', 'or':   '000000', 'slt':  '000000',
    'jr':   '000000', 'sll':  '000000', 'srl':  '000000', 'sra':  '000000',
    'lw':   '100011', 'sw':   '101011', 'beq':  '000100', 'bne':  '000101',
    'addi': '001000', 'andi': '001100', 'ori':  '001101', 'slti': '001010',
    'j':    '000010', 'jal':  '000011'
}

funct_table = {
    'add':  '100000', 'sub':  '100010', 'and': '100100', 'or':  '100101', 'slt':  '101010',
    'jr':   '001000', 'sll':  '000000', 'srl': '000010', 'sra': '000011'
}

def to_bin(value, bits):
    if value < 0:
        value = (1 << bits) + value
    return format(value, f'0{bits}b')[-bits:]

def reg_bin(reg):
    if reg not in registers:
        raise ValueError(f"Unknown register: {reg}")
    return to_bin(registers[reg], 5)

def assemble(instruction):
    instruction = instruction.replace(',', '').strip()
    parts = instruction.split()
    instr = parts[0]

    if instr in funct_table:  # R-type
        if instr in ['sll', 'srl', 'sra']:
            rd, rt, shamt = parts[1], parts[2], int(parts[3])
            return opcode_table[instr] + reg_bin('$zero') + reg_bin(rt) + reg_bin(rd) + to_bin(shamt, 5) + funct_table[instr]
        elif instr == 'jr':
            rs = parts[1]
            return opcode_table[instr] + reg_bin(rs) + '00000' + '00000' + '00000' + funct_table[instr]
        else:
            rd, rs, rt = parts[1], parts[2], parts[3]
            return opcode_table[instr] + reg_bin(rs) + reg_bin(rt) + reg_bin(rd) + '00000' + funct_table[instr]

    elif instr in ['lw', 'sw']:
        rt, offset_rs = parts[1], parts[2]
        match = re.match(r'(-?\d+)\((\$[a-z0-9]+)\)', offset_rs)
        if not match:
            raise ValueError("Expected offset(base) format.")
        offset, rs = int(match.group(1)), match.group(2)
        return opcode_table[instr] + reg_bin(rs) + reg_bin(rt) + to_bin(offset, 16)

    elif instr in ['beq', 'bne', 'addi', 'andi', 'ori', 'slti']:
        rt, rs, imm = parts[1], parts[2], int(parts[3])
        return opcode_table[instr] + reg_bin(rs) + reg_bin(rt) + to_bin(imm, 16)

    elif instr in ['j', 'jal']:
        address = int(parts[1])  # Assume already divided by 4
        return opcode_table[instr] + to_bin(address, 26)

    else:
        raise ValueError(f"Unsupported instruction: {instr}")

# Example usage:
if __name__ == "__main__":
    sample_instructions = [
        "add $t0, $t1, $t2",
        "lw $t0, 0($t1)",
        "beq $t0, $t1, 4",
        "sll $t0, $t1, 3",
        "j 1000"
    ]
    for inst in sample_instructions:
        try:
            print(f"{inst:<25} => {assemble(inst)}")
        except Exception as e:
            print(f"Error: {inst} -> {e}")
