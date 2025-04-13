# 🧩 CSE Bubble: Mini MIPS Processor — A Modular Single-Cycle CPU Design

This documentation details the design and implementation of a **mini MIPS-like processor** developed as a core project under Prof. Debapriya Roy Basu at **IIT Kanpur**. 

---

## Table of Contents

1. [Processor Overview](#processor-overview)  
2. [Modules Description](#modules-description)
   - [1. Program Counter (PC)](#1-program-counter-pc)
   - [2. Instruction Memory](#2-instruction-memory)
   - [3. Control Unit](#3-control-unit)
   - [4. Register File](#4-register-file)
   - [5. ALU Control](#5-alu-control)
   - [6. ALU](#6-alu)
   - [7. Data Memory](#7-data-memory)
   - [8. Sign Extender](#8-sign-extender)
   - [9. Shift Left 2](#9-shift-left-2)
   - [10. Multiplexers (MUXes)](#10-multiplexers-muxes)
   - [11. Jump and Link (jal), Jump Register (jr)](#11-jump-and-link-jal-jump-register-jr)
3. [Instruction Format](#instruction-format)
4. [Opcode Table](#opcode-table)
5. [ALU Operations](#alu-operations)
6. [ALU Control Table](#alu-control-table)
7. [Function Table (for R-type)](#function-table-for-r-type)
8. [ALU Control Unit](#alu-control-unit)
9. [Control Decoder](#control-decoder)
10. [Control Signal Table](#control-signal-table)
11. Processor Control & PC Notes(processor-control)

---

## 🧠 Processor Overview

This project implements a **single-cycle, 32-bit processor** inspired by the MIPS architecture. It is built from the ground up using Verilog and follows a modular approach for clarity and extensibility.

### Key Features:
- **32 general-purpose registers** (`$0` to `$31`), where `$0` is hardwired to zero.
- **Single-cycle execution**: Each instruction is fetched, decoded, executed, and written back in one clock cycle.
- **Support for core instruction types**:
  - **R-type**: Arithmetic and logical operations (`add`, `sub`, `and`, `or`, `slt`, etc.)
  - **I-type**: Immediate operations and memory access (`addi`, `lw`, `sw`, `beq`, `bne`, etc.)
  - **J-type**: Unconditional and linkable jumps (`j`, `jal`), along with `jr` for register-based jumps.
- **Modular design**:
  - Each component (ALU, Register File, Control Unit, etc.) is implemented as a separate module for ease of debugging and scalability.
  - Facilitates future extensions like pipelining, hazard detection, and interrupt handling.
---

## 🔧 Modules Description

### 1. Program Counter (PC)
- 32-bit register holding the current instruction address.
- Updates: `PC + 4`, `PC + 4 + (imm << 2)`, `register value (jr)`, or `(target << 2)`.

### 2. Instruction Memory
- Stores instructions in a word-addressable format.
- Fetches instructions based on the PC.

### 3. Control Unit
- Takes a 6-bit opcode as input.
- Outputs control signals to manage the datapath.

### 4. Register File
- 32 registers, 32 bits each.
- Two read ports, one write port.
- `Reg[0]` is always 0.

### 5. ALU Control
- Generates ALU control signals based on ALUOp and funct fields.

### 6. ALU
- Executes operations: add, sub, and, or, slt.
- Produces results and zero flag.

### 7. Data Memory
- Used for `lw` and `sw` instructions.
- Memory-mapped and byte-addressable.

### 8. Sign Extender
- Converts 16-bit immediate to 32-bit signed value.

### 9. Shift Left 2
- Shifts a 32-bit value left by 2 (for branches and jumps).

### 10. Multiplexers
- Select inputs to ALU, Register destination, and PC updates.

### 11. Jump and Link (`jal`) & Jump Register (`jr`)
- **`jal`**: `PC+4 → $ra (reg[31])`, `PC → target`.
- **`jr`**: `PC ← value in register rs`.

---

## 📘 Instruction Format

### R-type
| op (6) | rs (5) | rt (5) | rd (5) | shamt (5) | funct (6) |

### I-type
| op (6) | rs (5) | rt (5) | immediate (16) |

### J-type
| op (6) | address (26) |

---

## 📊 Opcode Table

| Instruction | Type | Opcode (binary) |
|-------------|------|------------------|
| R-type      | R    | 000000           |
| lw          | I    | 100011           |
| sw          | I    | 101011           |
| beq         | I    | 000100           |
| bne         | I    | 000101           |
| addi        | I    | 001000           |
| andi        | I    | 001100           |
| ori         | I    | 001101           |
| slti        | I    | 001010           |
| j           | J    | 000010           |
| jal         | J    | 000011           |

---

## ⚙️ ALU Operations

The ALU (Arithmetic Logic Unit) performs computations based on a 4-bit control signal `alu_control`. It supports arithmetic, logical, shift, and multiplication/division operations. Additional `hi` and `lo` outputs are used for storing results of multiplication and division.

### Inputs and Outputs:
- `a`, `b` : 32-bit operands
- `alu_control` : 4-bit signal controlling the operation
- `shift` : 6-bit shift amount used in shift instructions
- `out` : 32-bit result of most operations
- `hi`, `lo` : Used in mult/div instructions
- `zero` : High (`1`) when `out` equals zero, used in branch logic

---

### 🔍 ALU Control Table

| ALU Control | Operation      | Description |
|-------------|----------------|-------------|
| `0000`      | AND            | `out = a & b` |
| `0001`      | OR             | `out = a \| b` |
| `0010`      | ADD            | `out = a + b` |
| `0011`      | XOR            | `out = a ^ b` |
| `0100`      | NOR            | `out = ~(a \| b)` |
| `0101`      | SUB            | `out = a - b` |
| `0110`      | SLT (signed)   | `out = ($signed(a) < $signed(b)) ? 1 : 0` |
| `0111`      | SLT (unsigned) | `out = (a < b) ? 1 : 0` |
| `1001`      | SLL            | `out = b << shift` (Logical Left Shift) |
| `1010`      | SRL            | `out = b >> shift` (Logical Right Shift) |
| `1011`      | SRA            | `out = b >>> shift` (Arithmetic Right Shift) |
| `1100`      | MULT (signed)  | `{hi, lo} = $signed(a) * $signed(b)` |
| `1101`      | MULTU          | `{hi, lo} = a * b` (Unsigned) |
| `1110`      | DIV (signed)   | `lo = $signed(a) / $signed(b)`, `hi = $signed(a) % $signed(b)` |
| `1111`      | DIVU           | `lo = a / b`, `hi = a % b` (Unsigned) |

---

### ✅ Special Behavior
- **Zero flag**: `assign zero = (out == 0);`  
  Used for conditional branches like `beq` or `bne`.

- **Shift operations** use the `shift` input directly from the instruction (e.g., `shamt` field).

- **`hi` and `lo` registers**: Used in multiply/divide operations as per MIPS convention. Results are split:
  - For multiplication: `hi` stores the upper 32 bits, `lo` the lower.
  - For division: `lo` stores the quotient, `hi` the remainder.

> This ALU design supports both arithmetic and control flow needs of the MIPS-like processor and is easily extendable for more complex instructions.


---
## 🔢 Function Table (R-type)

| Instruction | funct  | Operation     |
|-------------|--------|---------------|
| add         | 100000 | Addition      |
| sub         | 100010 | Subtraction   |
| and         | 100100 | AND           |
| or          | 100101 | OR            |
| slt         | 101010 | Set less than |
| jr          | 001000 | Jump Register |

---

## 🧩 ALU Control Unit

The **ALU Control Unit** is responsible for converting the higher-level `alu_op` signal (from the main control unit) and the `func_code` field (for R-type instructions) into the specific `alu_control` signal that drives the ALU.

---

### 🔗 Inputs and Output

- `alu_op` : 2-bit signal from the Main Control Unit
- `func_code` : 6-bit function field from R-type instructions
- `alu_control` : 4-bit signal sent to the ALU

---

### 🎯 Mapping Table

#### I-type and Load/Store Instructions

| `alu_op` | Meaning         | `alu_control` | Operation |
|----------|------------------|---------------|-----------|
| `00`     | Load/Store       | `0010`        | ADD       |
| `01`     | Branch (beq, bne)| `0101`        | SUB       |

#### R-type Instructions (`alu_op = 10`)

| `func_code` | MIPS Instruction | `alu_control` | ALU Operation |
|-------------|------------------|---------------|---------------|
| `000000`    | `sll`            | `1001`        | Shift Left Logical |
| `000010`    | `srl`            | `1010`        | Shift Right Logical |
| `000011`    | `sra`            | `1011`        | Shift Right Arithmetic |
| `100000`    | `add`            | `0010`        | ADD |
| `100001`    | `addu`           | `0010`        | ADD |
| `100010`    | `sub`            | `0101`        | SUB |
| `100011`    | `subu`           | `0101`        | SUB |
| `100100`    | `and`            | `0000`        | AND |
| `100101`    | `or`             | `0001`        | OR |
| `100110`    | `xor`            | `0011`        | XOR |
| `100111`    | `nor`            | `0100`        | NOR |
| `101010`    | `slt`            | `0111`        | SLT (unsigned) |
| `101011`    | `sltu`           | `0110`        | SLT (signed) |
| `011000`    | `mult`           | `1100`        | MULT (signed) |
| `011001`    | `multu`          | `1101`        | MULT (unsigned) |
| `011010`    | `div`            | `1110`        | DIV (signed) |
| `011011`    | `divu`           | `1111`        | DIV (unsigned) |

> Any unsupported or unknown combination defaults `alu_control` to `0000` (NOP behavior).
---
## 🎮 Control Decoder

The **Control Decoder** interprets the 6-bit opcode (and, for R-type, the `func_code`) to generate the appropriate control signals required to drive the datapath.

This module is essentially the brain behind deciding how different instructions behave in the processor.

---

### 🔗 Inputs and Outputs

- **Input:** `instruction[31:0]` – The complete instruction word  
- **Input:** `func_code[5:0]` – Function field (for R-type)
- **Output:**  
  - `reg_dst` – Selects destination register (rd vs rt)
  - `alu_src` – Chooses ALU input (register or immediate)
  - `mem_to_reg` – Selects ALU result or memory data for register write
  - `reg_write` – Enables register write
  - `mem_read` – Enables memory read
  - `mem_write` – Enables memory write
  - `branch` – Controls BEQ
  - `branch_not_equal` – Controls BNE
  - `alu_op[1:0]` – Encodes operation type for the ALU Control Unit
  - `mfhi_en`, `mflo_en` – Enables `mfhi` or `mflo` write-back

---

### 🧭 Control Signal Table

#### ✅ R-type Instructions (`opcode = 000000`)

| `func_code` | Instruction | reg_dst | alu_src | reg_write | alu_op | Special |
|-------------|-------------|---------|---------|-----------|--------|---------|
| `010000`    | `mfhi`      |   1     |   0     |     1     | Don't care | `mfhi_en = 1` |
| `010010`    | `mflo`      |   1     |   0     |     1     | Don't care | `mflo_en = 1` |
| `011000`–`011011` | `mult`, `div` | x | x | **0** | 10 | ALU only (no reg write) |
| others      | `add`, `sub`, etc. | 1 | 0 | 1 | 10 | Regular R-type |

#### 📥 Load Instruction

| Opcode     | Instruction | alu_src | mem_read | reg_write | mem_to_reg |
|------------|-------------|---------|----------|-----------|------------|
| `100011`   | `lw`        | 1       | 1        | 1         | 1          |

#### 📤 Store Instruction

| Opcode     | Instruction | alu_src | mem_write |
|------------|-------------|---------|------------|
| `101011`   | `sw`        | 1       | 1          |

#### 🔁 Branch Instructions

| Opcode     | Instruction | branch | branch_not_equal | alu_op |
|------------|-------------|--------|------------------|--------|
| `000100`   | `beq`       | 1      | 0                | 01     |
| `000101`   | `bne`       | 0      | 1                | 01     |

#### 🔀 Jump and Link

| Opcode     | Instruction | reg_write |
|------------|-------------|-----------|
| `000011`   | `jal`       | 1         |

---

### 🧠 Functional Behavior Summary

- **R-type instructions** (`opcode = 000000`) are further decoded using the `func_code`. Special cases like `mfhi`, `mflo`, `mult`, and `div` are handled with dedicated enables (`mfhi_en`, `mflo_en`) and write control.
- **Non-R-type instructions** (`lw`, `sw`, `beq`, `bne`, `jal`) are decoded directly from the opcode.
- The `alu_op` field is used to delegate responsibility:
  - `alu_op = 00` → Use default ALU operation (e.g., `ADD` for `lw`, `sw`)
  - `alu_op = 01` → Use `SUB` for branches like `beq` and `bne`
  - `alu_op = 10` → Use `func_code` for detailed ALU control (R-type)
- This design follows the **modular MIPS pipeline** philosophy:  
  The **Control Decoder** handles high-level control, while the **ALU Control Unit** independently determines specific ALU operations, improving reusability and scalability.
- All control signals are **zeroed by default** to ensure safe behavior for undefined or unsupported instructions.

---

This Control Decoder ensures accurate signal generation to route data correctly across the datapath, enabling the MIPS processor to handle a variety of instructions including arithmetic, memory access, and control flow.

---

## 📝 **Processor Control & PC Update Notes**

### 📌 **Register and Special Functionality**

- **Register 31** is reserved as the **return address** for the `jal` instruction.

### 📌 **Program Counter (PC) Updates**

The **Program Counter (PC)** is updated in different ways depending on the type of instruction being executed:

1. **Default Behavior (Non-Branch, Non-Jump Instructions)**:
   - `PC = PC + 4`
   
2. **Branch Instructions (BEQ, BNE)**:
   - `PC = PC + 4 + (sign_extended_imm << 2)`
   - The `sign_extended_imm` is shifted left by 2 to account for byte addresses.

3. **Jump Instructions (J, JAL)**:
   - `PC = {PC[31:28], addr, 00}`
   - The `addr` is the target address, and the `00` is appended to align to word boundaries (since MIPS instructions are word-aligned).

4. **Jump Register (JR)**:
   - `PC = reg[rs]`
   - The target address is stored in the register `rs`, used for jumps like `jr` (jump register).

---

## 🛠️ Possible Extensions

- Add support for multiplication/division
- Implement pipelining (IF, ID, EX, MEM, WB)
- Add forwarding and hazard detection
- Interrupt and exception handling

---
