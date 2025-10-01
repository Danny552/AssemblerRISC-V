.data
# --- Basic scalars ---
w1:     .word 19              # Word at addr 0
b1:     .byte 5               # Byte (check .half alignment)
h1:     .half 300             # Halfword (check padding/alignment)
w2:     .word -1              # Negative word, 0xFFFFFFFF

# --- Strings ---
msg2:   .string "Test"        # With null terminator

# --- Space (alignment filler) ---

.text
main:
    # --- R-type ---
    add a0, a1, a2
    sub t0, t1, t2
    slt s1, a0, a1
    xor s2, s3, s4

    # --- I-type ---
    addi a0, zero, -1         # Negative immediate
    xori a1, a1, 0xFF         # Large positive immediate

    # --- Shifts ---
    slli a5, a6, 31           # Max shamt
    srli a5, a5, 1
    srai a5, a5, 15

    # --- Branches ---
    beq a0, a1, equal
    bne a0, a1, notequal
    blt a0, a1, less
    bge a0, a1, greater

equal:
    nop
    j end

notequal:
    mv t0, a0
    j end

less:
    neg t1, a1
    j end

greater:
    not t2, a2
    j end

end:
    # --- U-type ---
    lui t3, 0xABCDE
    auipc t4, 0x12345

    # --- Jumps ---
    jal other                 # Jump forwards

    ret                       # Should expand to jalr x0, x1, 0

other:
    ecall
    ebreak
