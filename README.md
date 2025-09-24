# RISC-V Assembler (RV32I Subset + Basic Pseudo-Instructions)

**Universidad Tecnológica de Pereira – 2025-2**  

**Authors:**  
- Daniel Alejandro Henao – 1114150552  
- Juan Camilo Cano – 1137059546  

---

## Overview

This Python-based assembler translates RISC-V assembly code (RV32I subset) into both binary and hexadecimal machine code. It supports base integer instructions, basic pseudo-instructions, and data section directives, providing proper memory alignment and label resolution.

---

## Features

- **Instruction Set Support:**  
  - RV32I base instructions: R, I, S, B, U, J types  
  - Partial pseudo-instructions: `nop`, `mv`, `neg`, `ret`, etc.  

- **Data Section Directives:**  
  - `.word`, `.half`, `.byte`  
  - `.ascii`, `.asciiz`, `.string`  
  - `.space`  
  - Ensures correct memory alignment for multi-byte data  

- **Label Management:**  
  - Resolves labels in `.text` and `.data` sections  
  - Supports branch and jump label offsets  

---

## Limitations

- Only supports RV32I integer instructions  
- Pseudo-instructions are partially implemented (`la`, `call`, `tail` not included)  
- Branch/jump offsets limited by instruction format  

---
## Usage
```
python assembler.py program.asm program.hex program.bin
```