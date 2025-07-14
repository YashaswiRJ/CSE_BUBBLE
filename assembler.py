import sys

# Instruction formats
R_TYPE = 0
I_TYPE = 1
J_TYPE = 2

# Register mapping
registers = {
    '$0': 0, '$zero': 0,
    '$1': 1, '$at': 1,
    '$2': 2, '$v0': 2,
    '$3': 3, '$v1': 3,
    '$4': 4, '$a0': 4,
    '$5': 5, '$a1': 5,
    '$6': 6, '$a2': 6,
    '$7': 7, '$a3': 7,
    '$8': 8, '$t0': 8,
    '$9': 9, '$t1': 9,
    '$10': 10, '$t2': 10,
    '$11': 11, '$t3': 11,
    '$12': 12, '$t4': 12,
    '$13': 13, '$t5': 13,
    '$14': 14, '$t6': 14,
    '$15': 15, '$t7': 15,
    '$16': 16, '$s0': 16,
    '$17': 17, '$s1': 17,
    '$18': 18, '$s2': 18,
    '$19': 19, '$s3': 19,
    '$20': 20, '$s4': 20,
    '$21': 21, '$s5': 21,
    '$22': 22, '$s6': 22,
    '$23': 23, '$s7': 23,
    '$24': 24, '$t8': 24,
    '$25': 25, '$t9': 25,
    '$26': 26, '$k0': 26,
    '$27': 27, '$k1': 27,
    '$28': 28, '$gp': 28,
    '$29': 29, '$sp': 29,
    '$30': 30, '$fp': 30,
    '$31': 31, '$ra': 31
}

# Opcode mapping
opcodes = {
    'add':  ('000000', R_TYPE),
    'sub':  ('000000', R_TYPE),
    'and':  ('000000', R_TYPE),
    'or':   ('000000', R_TYPE),
    'slt':  ('000000', R_TYPE),
    'addi': ('001000', I_TYPE),
    'andi': ('001100', I_TYPE),
    'ori':  ('001101', I_TYPE),
    'slti': ('001010', I_TYPE),
    'lw':   ('100011', I_TYPE),
    'sw':   ('101011', I_TYPE),
    'beq':  ('000100', I_TYPE),
    'bne':  ('000101', I_TYPE),
    'j':    ('000010', J_TYPE),
    'jal':  ('000011', J_TYPE),
    'jr':   ('000000', R_TYPE),
    'sll':  ('000000', R_TYPE),
    'srl':  ('000000', R_TYPE),
    'sra':  ('000000', R_TYPE),
    'mult': ('000000', R_TYPE),
    'multu':('000000', R_TYPE),
    'div':  ('000000', R_TYPE),
    'divu': ('000000', R_TYPE),
    'mfhi': ('000000', R_TYPE),
    'mflo': ('000000', R_TYPE)
}

# Function code mapping
funct_codes = {
    'add':   '100000',
    'sub':   '100010',
    'and':   '100100',
    'or':    '100101',
    'slt':   '101010',
    'jr':    '001000',
    'sll':   '000000',
    'srl':   '000010',
    'sra':   '000011',
    'mult':  '011000',
    'multu': '011001',
    'div':   '011010',
    'divu':  '011011',
    'mfhi':  '010000',
    'mflo':  '010010'
}

def parse_instruction(line):
    """Parse a single line of assembly code into components"""
    # Remove comments
    line = line.split('#')[0].strip()
    if not line:
        return None
    
    # Split into instruction and operands
    parts = [p.strip() for p in line.split(maxsplit=1)]
    if len(parts) < 1:
        return None
    
    mnemonic = parts[0].lower()
    operands = []
    
    if len(parts) > 1:
        # Split operands, handling possible parentheses for lw/sw
        operands = [op.strip() for op in parts[1].split(',')]
        
        # Handle lw/sw format: rt, offset(rs)
        if mnemonic in ['lw', 'sw'] and len(operands) == 2:
            offset_part = operands[1].split('(')
            if len(offset_part) == 2:
                offset = offset_part[0]
                rs = offset_part[1].replace(')', '')
                operands = [operands[0], offset, rs]
    
    return {'mnemonic': mnemonic, 'operands': operands}

def assemble_instruction(instruction, labels=None, current_address=0):
    """Convert a parsed instruction to binary machine code"""
    if not instruction:
        return None
    
    mnemonic = instruction['mnemonic']
    operands = instruction['operands']
    
    if mnemonic not in opcodes:
        raise ValueError(f"Unknown instruction: {mnemonic}")
    
    opcode, inst_type = opcodes[mnemonic]
    
    if inst_type == R_TYPE:
        return assemble_r_type(mnemonic, operands)
    elif inst_type == I_TYPE:
        return assemble_i_type(mnemonic, operands, labels, current_address)
    elif inst_type == J_TYPE:
        return assemble_j_type(mnemonic, operands, labels, current_address)
    else:
        raise ValueError(f"Unknown instruction type for {mnemonic}")

def assemble_r_type(mnemonic, operands):
    """Assemble R-type instructions"""
    if mnemonic in ['jr']:
        # jr $rs
        if len(operands) != 1:
            raise ValueError(f"Invalid operands for {mnemonic}")
        
        rs = parse_register(operands[0])
        shamt = '00000'
        rd = '00000'
        funct = funct_codes[mnemonic]
        
        return opcode + rs + '00000' + rd + shamt + funct
    
    elif mnemonic in ['sll', 'srl', 'sra']:
        # sll $rd, $rt, shamt
        if len(operands) != 3:
            raise ValueError(f"Invalid operands for {mnemonic}")
        
        rd = parse_register(operands[0])
        rt = parse_register(operands[1])
        shamt = parse_immediate(operands[2], 5, unsigned=True)
        rs = '00000'
        funct = funct_codes[mnemonic]
        
        return opcode + rs + rt + rd + shamt + funct
    
    elif mnemonic in ['mfhi', 'mflo']:
        # mfhi $rd or mflo $rd
        if len(operands) != 1:
            raise ValueError(f"Invalid operands for {mnemonic}")
        
        rd = parse_register(operands[0])
        rs = '00000'
        rt = '00000'
        shamt = '00000'
        funct = funct_codes[mnemonic]
        
        return opcode + rs + rt + rd + shamt + funct
    
    elif mnemonic in ['mult', 'multu', 'div', 'divu']:
        # mult $rs, $rt
        if len(operands) != 2:
            raise ValueError(f"Invalid operands for {mnemonic}")
        
        rs = parse_register(operands[0])
        rt = parse_register(operands[1])
        rd = '00000'
        shamt = '00000'
        funct = funct_codes[mnemonic]
        
        return opcode + rs + rt + rd + shamt + funct
    
    else:
        # Standard R-type: add $rd, $rs, $rt
        if len(operands) != 3:
            raise ValueError(f"Invalid operands for {mnemonic}")
        
        rd = parse_register(operands[0])
        rs = parse_register(operands[1])
        rt = parse_register(operands[2])
        shamt = '00000'
        funct = funct_codes[mnemonic]
        
        return opcode + rs + rt + rd + shamt + funct

def assemble_i_type(mnemonic, operands, labels, current_address):
    """Assemble I-type instructions"""
    opcode = opcodes[mnemonic][0]
    
    if mnemonic in ['lw', 'sw']:
        # lw $rt, offset($rs) or sw $rt, offset($rs)
        if len(operands) != 3:
            raise ValueError(f"Invalid operands for {mnemonic}")
        
        rt = parse_register(operands[0])
        imm = parse_immediate(operands[1], 16)
        rs = parse_register(operands[2])
        
        return opcode + rs + rt + imm
    
    elif mnemonic in ['beq', 'bne']:
        # beq $rs, $rt, label
        if len(operands) != 3:
            raise ValueError(f"Invalid operands for {mnemonic}")
        
        rs = parse_register(operands[0])
        rt = parse_register(operands[1])
        
        # Calculate branch offset
        if labels and operands[2] in labels:
            target_address = labels[operands[2]]
            offset = (target_address - (current_address + 4)) // 4
            imm = parse_immediate(str(offset), 16)
        else:
            # Assume it's a numeric offset
            imm = parse_immediate(operands[2], 16)
        
        return opcode + rs + rt + imm
    
    else:
        # addi $rt, $rs, imm or andi $rt, $rs, imm, etc.
        if len(operands) != 3:
            raise ValueError(f"Invalid operands for {mnemonic}")
        
        rt = parse_register(operands[0])
        rs = parse_register(operands[1])
        imm = parse_immediate(operands[2], 16, unsigned=(mnemonic in ['andi', 'ori']))
        
        return opcode + rs + rt + imm

def assemble_j_type(mnemonic, operands, labels, current_address):
    """Assemble J-type instructions"""
    opcode = opcodes[mnemonic][0]
    
    if mnemonic in ['j', 'jal']:
        # j target or jal target
        if len(operands) != 1:
            raise ValueError(f"Invalid operands for {mnemonic}")
        
        target = operands[0]
        
        if labels and target in labels:
            # Use label address
            address = labels[target]
            # J-type uses word address (divide by 4)
            address_bits = format(address // 4, '026b')
        else:
            # Assume it's a direct address
            try:
                address = int(target)
                address_bits = format(address, '026b')
            except ValueError:
                raise ValueError(f"Invalid target address: {target}")
        
        return opcode + address_bits
    
    else:
        raise ValueError(f"Unsupported J-type instruction: {mnemonic}")

def parse_register(reg):
    """Convert register name to 5-bit binary string"""
    if reg not in registers:
        raise ValueError(f"Unknown register: {reg}")
    return format(registers[reg], '05b')

def parse_immediate(value, bits, unsigned=False):
    """Convert immediate value to binary string of specified bits"""
    try:
        num = int(value)
    except ValueError:
        # Handle hexadecimal or binary literals
        if value.startswith('0x'):
            num = int(value[2:], 16)
        elif value.startswith('0b'):
            num = int(value[2:], 2)
        else:
            raise ValueError(f"Invalid immediate value: {value}")
    
    if unsigned:
        if num < 0 or num >= (1 << bits):
            raise ValueError(f"Unsigned immediate {num} out of range for {bits} bits")
        return format(num, f'0{bits}b')
    else:
        min_val = -(1 << (bits - 1))
        max_val = (1 << (bits - 1)) - 1
        if num < min_val or num > max_val:
            raise ValueError(f"Signed immediate {num} out of range for {bits} bits")
        # Convert to 2's complement
        if num < 0:
            num = (1 << bits) + num
        return format(num, f'0{bits}b')

def first_pass(lines):
    """First pass to collect labels and their addresses"""
    labels = {}
    address = 0
    
    for line in lines:
        # Remove comments and whitespace
        clean_line = line.split('#')[0].strip()
        if not clean_line:
            continue
        
        # Check for label
        if ':' in clean_line:
            label_part, rest = clean_line.split(':', 1)
            label = label_part.strip()
            if label in labels:
                raise ValueError(f"Duplicate label: {label}")
            labels[label] = address
            clean_line = rest.strip()
            if not clean_line:
                continue
        
        # Check if line has an instruction
        parts = clean_line.split(maxsplit=1)
        if parts:
            address += 4  # Each instruction is 4 bytes
    
    return labels

def assemble(lines):
    """Assemble a complete program"""
    # First pass to collect labels
    labels = first_pass(lines)
    
    # Second pass to generate machine code
    machine_code = []
    address = 0
    
    for line in lines:
        # Remove comments and whitespace
        clean_line = line.split('#')[0].strip()
        if not clean_line:
            continue
        
        # Handle labels (already processed in first pass)
        if ':' in clean_line:
            _, rest = clean_line.split(':', 1)
            clean_line = rest.strip()
            if not clean_line:
                continue
        
        # Parse and assemble instruction
        parsed = parse_instruction(clean_line)
        if parsed:
            binary = assemble_instruction(parsed, labels, address)
            if binary:
                machine_code.append(binary)
                address += 4
    
    return machine_code

def main():
    if len(sys.argv) != 2:
        print("Usage: python assembler.py <input_file.asm>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    
    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
        
        machine_code = assemble(lines)
        
        # Output to console and file
        output_file = input_file.replace('.asm', '.bin')
        with open(output_file, 'w') as f:
            for code in machine_code:
                print(code)
                f.write(code + '\n')
        
        print(f"Assembly successful. Output written to {output_file}")
    
    except Exception as e:
        print(f"Error during assembly: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
